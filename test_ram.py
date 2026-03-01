import sys, os
sys.path.append('/opt/clamfox')
from clamav_host import update_intelligence, load_url_cache, _url_cache
print("Force updating into RAM...")
update_intelligence(force=True)
load_url_cache(force=True)
from clamav_host import _url_cache
print("After RAM update, cache size:", 0 if _url_cache is None else len(_url_cache))
