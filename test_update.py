import sys, os
sys.path.append('/home/ovidio/firefox_clamav/host')
from clamav_host import update_intelligence, load_url_cache, _url_cache
print("Before update, cache size:", 0 if _url_cache is None else len(_url_cache))
update_intelligence(force=True)
load_url_cache(force=True)
from clamav_host import _url_cache
print("After update, cache size:", 0 if _url_cache is None else len(_url_cache))
