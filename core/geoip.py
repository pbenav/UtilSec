import os
import logging

try:
    import maxminddb
except ImportError:
    maxminddb = None

logger = logging.getLogger("UtilSec.GeoIP")

class GeoIPLookup:
    def __init__(self, db_path="data/GeoLite2-Country.mmdb"):
        self.reader = None
        if maxminddb is None:
            logger.error("maxminddb library not installed. GeoIP disabled.")
            return
            
        if os.path.exists(db_path):
            try:
                self.reader = maxminddb.open_database(db_path)
            except Exception as e:
                logger.error("Failed to open GeoIP database %s: %s", db_path, e)
        else:
            logger.warning("GeoIP database not found at %s. GeoIP disabled.", db_path)
            
    def get_country(self, ip: str) -> str:
        if not self.reader:
            return "??"
        try:
            info = self.reader.get(ip)
            if info and 'country' in info and 'iso_code' in info['country']:
                return info['country']['iso_code']
        except Exception:
            pass
        return "??"

    def close(self):
        if self.reader:
            self.reader.close()

# Global singleton
geoip_lookup = GeoIPLookup()
