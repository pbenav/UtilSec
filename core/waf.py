import os
import subprocess
import logging

logger = logging.getLogger("UtilSec.WAF")

class WafManager:
    def __init__(self, conf_dir="/etc/apache2/modsecurity.d"):
        self.conf_dir = conf_dir
        self.conf_file = os.path.join(self.conf_dir, "utilsec_custom.conf")
        
    def is_modsec_installed(self) -> bool:
        """Check if ModSecurity is installed on an APT-based system."""
        try:
            res = subprocess.run(["dpkg", "-l", "libapache2-mod-security2"], capture_output=True, text=True)
            return "ii  libapache2-mod-security2" in res.stdout
        except Exception:
            return False
            
    def ensure_conf_file(self):
        if not os.path.exists(self.conf_dir):
            try:
                os.makedirs(self.conf_dir, exist_ok=True)
            except PermissionError:
                pass
        
        if not os.path.exists(self.conf_file):
            try:
                with open(self.conf_file, 'w') as f:
                    f.write("# UtilSec Custom WAF Rules\n")
                    f.write("# Include this file in your ModSecurity configuration\n\n")
            except PermissionError:
                pass

    def get_custom_rules(self) -> list:
        if not os.path.exists(self.conf_file):
            return []
            
        rules = []
        try:
            with open(self.conf_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SecRule"):
                        rules.append(line)
        except Exception:
            pass
        return rules

    def add_custom_rule(self, directive: str) -> bool:
        self.ensure_conf_file()
        try:
            with open(self.conf_file, 'a') as f:
                f.write(f"{directive}\n")
            # Reload apache
            subprocess.run(["systemctl", "reload", "apache2"], capture_output=True)
            return True
        except Exception as e:
            logger.error(f"Failed to add WAF rule: {e}")
            return False
            
    def remove_custom_rule(self, idx: int) -> bool:
        rules = self.get_custom_rules()
        if idx < 0 or idx >= len(rules):
            return False
            
        rules.pop(idx)
        try:
            with open(self.conf_file, 'w') as f:
                f.write("# UtilSec Custom WAF Rules\n\n")
                for r in rules:
                    f.write(f"{r}\n")
            subprocess.run(["systemctl", "reload", "apache2"], capture_output=True)
            return True
        except Exception:
            return False

    def edit_custom_rule(self, idx: int, directive: str) -> bool:
        rules = self.get_custom_rules()
        if idx < 0 or idx >= len(rules):
            return False
            
        rules[idx] = directive
        try:
            with open(self.conf_file, 'w') as f:
                f.write("# UtilSec Custom WAF Rules\n\n")
                for r in rules:
                    f.write(f"{r}\n")
            subprocess.run(["systemctl", "reload", "apache2"], capture_output=True)
            return True
        except Exception:
            return False


waf_mgr = WafManager()
