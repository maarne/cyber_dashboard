"""Private source-only validator. No app config, DB, samples, plugins or includes."""
import json
import os
import re
import resource
import sys
from importlib.metadata import version
from uuid import UUID

NOTICE = 'Syntax/structure validation is not proof of detection efficacy or SIEM compatibility.'


def sigma(source):
    import yaml
    from yaml.events import AliasEvent, CollectionStartEvent, CollectionEndEvent
    from sigma.rule import SigmaRule
    depth = nodes = 0
    for event in yaml.parse(source):
        nodes += 1
        if isinstance(event, AliasEvent) or getattr(event,'anchor',None) or getattr(event,'tag',None):
            raise ValueError('YAML aliases, anchors and explicit/custom tags are unsupported.')
        if isinstance(event,CollectionStartEvent): depth += 1
        if isinstance(event,CollectionEndEvent): depth -= 1
        if depth>20 or nodes>10000: raise ValueError('YAML nesting/node limit exceeded.')

    class UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self,node,deep=False):
            keys=[self.construct_object(k,deep=deep) for k,_ in node.value]
            if len(set(keys))!=len(keys): raise ValueError('Duplicate YAML mapping keys are unsupported.')
            return super().construct_mapping(node,deep)

    doc=yaml.load(source,Loader=UniqueLoader)
    if not isinstance(doc,dict): raise ValueError('Exactly one Sigma mapping/document is required.')
    for field in ('title','id','status','level','logsource','detection'):
        if not doc.get(field): raise ValueError(f'Sigma field {field} is required by this validation policy.')
    if not isinstance(doc['id'],str) or str(UUID(doc['id']))!=doc['id'].lower(): raise ValueError('Use a canonical Sigma UUID.')
    if doc['level'] not in ('informational','low','medium','high','critical'): raise ValueError('Unsupported Sigma level.')
    if doc['status'] not in ('experimental','test','stable','deprecated','unsupported'): raise ValueError('Unsupported Sigma status.')
    if not isinstance(doc['logsource'],dict) or not any(doc['logsource'].get(k) for k in ('category','product','service')):
        raise ValueError('A non-empty logsource category/product/service is required.')
    if not isinstance(doc['detection'],dict) or 'timeframe' in doc['detection']:
        raise ValueError('A detection mapping is required; timeframe/aggregation conversion is not supported.')
    parsed=SigmaRule.from_dict(doc,collect_errors=False)
    for condition in parsed.detection.parsed_condition:
        condition.parsed  # Force the maintained parser to resolve every selector/condition.
    return []


def yara_source(source):
    import yara
    # Tokenize only outside quoted strings, regex strings and comments. No rule
    # includes or modules are accepted; compile() never receives a file path.
    tokens=re.findall(r'"(?:\\.|[^"\\])*"|/\*[\s\S]*?\*/|//[^\n]*|/(?:\\.|[^/\\\n])*/|\b[A-Za-z_][A-Za-z_0-9]*\b',source)
    if any(t in ('include','import') for t in tokens):
        raise ValueError('YARA includes and module imports are disabled.')
    compiled=yara.compile(source=source,includes=False)
    return list(compiled.warnings)


def main():
    resource.setrlimit(resource.RLIMIT_CPU,(2,2))
    resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,)*2)
    resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
    resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    try:
        import ctypes
        ctypes.CDLL(None).prctl(38,1,0,0,0)  # Linux no_new_privs; no elevated exec.
    except (ImportError,OSError):
        pass
    request=json.loads(sys.stdin.buffer.read(1600000))
    snapshot=request['snapshot']; source=snapshot['code_content']
    report={'status':'invalid','reason':'validation_failed','errors':[],'warnings':[NOTICE], 'validator_version':request['validator_version']}
    try:
        if not isinstance(source,str) or not 1<=len(source.encode())<=204800: raise ValueError('Source exceeds 200 KiB.')
        for field,pattern in (('target_cve',r'CVE-\d{4}-\d{4,}'),('mitre_ttp',r'T\d{4}(?:\.\d{3})?(?: - .{1,180})?')):
            value=snapshot.get(field) or ''
            if value and value!='N/A' and not re.fullmatch(pattern,value): raise ValueError(f'Invalid catalog {field} link.')
        if snapshot['rule_type'].upper()=='SIGMA':
            report['warnings'].extend(sigma(source))
        else:
            report['warnings'].extend(yara_source(source))
        if snapshot.get('target_siem') not in ('','Generic',None):
            report['warnings'].append('Target platform labels are not converted or integration-tested by this validator.')
        report.update(status='valid',reason='syntax_structure_valid')
    except (ImportError,ModuleNotFoundError) as exc:
        report.update(status='error',reason='dependency_unavailable',errors=[str(exc)[:500]])
    except MemoryError:
        report.update(status='error',reason='memory_limit',errors=['Validator exceeded its memory budget.'])
    except Exception as exc:
        report['errors']=[str(exc)[:1000]]
    report['warnings']=[str(v)[:1000] for v in report['warnings'][:20]]
    print(json.dumps(report,ensure_ascii=True))


if __name__=='__main__': main()
