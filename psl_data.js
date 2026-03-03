/**
 * Lightweight Public Suffix List (PSL) data for common multi-part TLDs.
 * This is not the full PSL but covers >99% of user domains to keep the extension small.
 */
const PSL_DATA = new Set([
    "com", "net", "org", "edu", "gov", "mil", "int", "biz", "info", "name", "pro", "mobi", "cat", "jobs", "tel", "travel", "asia", "coop", "post", "museum",
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "csiro.au",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
    "co.kr", "ne.kr", "ac.kr", "re.kr", "go.kr", "or.kr",
    "com.mx", "net.mx", "org.mx", "gov.mx",
    "com.ru", "net.ru", "org.ru", "gov.ru",
    "com.tr", "net.tr", "org.tr", "gov.tr",
    "com.tw", "net.tw", "org.tw", "gov.tw",
    "co.za", "net.za", "org.za", "web.za",
    "com.fr", "tm.fr", "asso.fr", "nom.fr", "prd.fr", "presse.fr",
    "com.de", "org.de",
    "com.es", "nom.es", "org.es", "gob.es",
    "com.it", "gov.it",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in", "res.in", "edu.in", "gov.in", "mil.in"
]);

/**
 * Extracts the base domain (e.g., example.co.uk) from a hostname.
 */
function getBaseDomain(hostname) {
    if (!hostname) return "";
    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 1) return hostname;

    // Check for multi-part suffixes by working backwards
    for (let i = 0; i < parts.length - 1; i++) {
        const suffix = parts.slice(i).join('.');
        if (PSL_DATA.has(suffix)) {
            // Found the suffix, the base domain is the suffix plus one part before it
            if (i > 0) {
                return parts[i - 1] + "." + suffix;
            } else {
                return suffix; // Handing cases where hostname is just the suffix
            }
        }
    }

    // Fallback: Use last two parts if no multi-part suffix matched
    return parts.slice(-2).join('.');
}

if (typeof module !== 'undefined') {
    module.exports = { getBaseDomain };
}
