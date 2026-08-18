import re

def test_modal_styles():
    with open("/home/maarne/apps/antigravity/cyber_dashboard/app/static/css/style.css") as f:
        css = f.read()

    assert ".modal-overlay" in css
    assert "overflow-y: auto" in css
    assert ".modal-card" in css
    assert "max-height" in css
    assert "display: flex" in css
    assert "flex-direction: column" in css
    assert ".modal-body" in css
    assert "overflow-y: auto" in css
    assert ".modal-card > form" in css

    with open("/home/maarne/apps/antigravity/cyber_dashboard/app/templates/rules.html") as f:
        html = f.read()

    assert "modal-card modal-card-lg" in html
    assert "guide-modal" in html
    assert "rule-modal" in html

    print("✅ Modal CSS and layout structure verified successfully!")

if __name__ == "__main__":
    test_modal_styles()
