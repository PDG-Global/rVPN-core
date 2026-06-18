//! Built-in domain lists for split tunneling and ad blocking
//! 
//! Data sources:
//! - China domains: github.com/felixonmars/dnsmasq-china-list
//! - Ad domains: Various blocklists (EasyList, uBlock, etc.)
//! 
//! Last updated: 2024-03-01

use std::collections::HashSet;
use std::sync::OnceLock;

/// China-specific domains that should bypass VPN
/// Sourced from dnsmasq-china-list and other China CDN lists
pub const CHINA_DOMAINS: &[&str] = &[
    // Major Chinese services
    "alicdn.com",
    "aliyun.com",
    "aliyuncs.com",
    "taobao.com",
    "tmall.com",
    "jd.com",
    "360buy.com",
    "360buyimg.com",
    "baidu.com",
    "bdimg.com",
    "bdstatic.com",
    "bcebos.com",
    "weibo.com",
    "sina.com.cn",
    "sinaimg.cn",
    "sinajs.cn",
    "qq.com",
    "tencent.com",
    "qpic.cn",
    "qlogo.cn",
    "gtimg.cn",
    "idqqimg.com",
    "wechat.com",
    "weixin.com",
    "wx.qq.com",
    "bilibili.com",
    "bilivideo.com",
    "hdslb.com",
    "youku.com",
    "ykimg.com",
    "iqiyi.com",
    "qy.net",
    "iqiyipic.com",
    "douyin.com",
    "iesdouyin.com",
    "douyinvod.com",
    "kuaishou.com",
    "ksapisrv.com",
    "xiami.com",
    "xiami.net",
    "netease.com",
    "126.net",
    "127.net",
    "163.com",
    "126.com",
    "yeah.net",
    "sohu.com",
    "sogou.com",
    "sogoucdn.com",
    "360.cn",
    "360.com",
    "360safe.com",
    "qhimg.com",
    "qhimgs.com",
    "qhmsg.com",
    "qhres.com",
    "qihucdn.com",
    "meituan.com",
    "meituan.net",
    "dianping.com",
    "xiaohongshu.com",
    "xhscdn.com",
    "zhihu.com",
    "zhimg.com",
    "v2ex.com",
    "douban.com",
    "doubanio.com",
    "jianshu.com",
    "jianshu.io",
    "csdn.net",
    "csdnimg.cn",
    "oschina.net",
    "gitee.com",
    "coding.net",
    "toutiao.com",
    "toutiaoimg.com",
    "toutiaocloud.com",
    "toutiaovod.com",
    "snssdk.com",
    "bytedance.com",
    "byteimg.com",
    "byted-static.com",
    "bytescm.com",
    "bytegoofy.com",
    "feishu.cn",
    "larksuite.com",
    "dingtalk.com",
    "alibaba.com",
    "alibaba-inc.com",
    "alicdn.net",
    "alibabacloud.com",
    "aliyun-inc.com",
    "alipay.com",
    "alipayobjects.com",
    "antfin.com",
    "antgroup.com",
    "mybank.cn",
    "cmbchina.com",
    "cmbimg.com",
    "icbc.com.cn",
    "ccb.com",
    "boc.cn",
    "bankcomm.com",
    "abchina.com",
    "psbc.com",
    "pingan.com",
    "pingan.com.cn",
    "amap.com",
    "autonavi.com",
    "gaode.com",
    "baidumap.com",
    "map.baidu.com",
    "qqmap.com",
    "map.qq.com",
    "here.com",
    "herecdn.com",
    "upyun.com",
    "upaiyun.com",
    "qiniu.com",
    "qiniudn.com",
    "qiniucdn.com",
    "qnssl.com",
    "qbox.me",
    "baidupcs.com",
    "baiducontent.com",
    "yun.baidu.com",
    "pan.baidu.com",
    "weiyun.com",
    "myqcloud.com",
    "qcloud.com",
    "tencent-cloud.com",
    "tencentcs.com",
    "tencentcos.cn",
    "hwclouds.com",
    "huaweicloud.com",
    "huaweicloud.cn",
    "hicloud.com",
    "dbankcloud.com",
    "dbankcdn.com",
    "aliyundrive.com",
    "alipan.com",
    "yunpan.cn",
    "115.com",
    "115cdn.com",
    "115cdn.net",
    "lanzou.com",
    "lanzoui.com",
    "lanzoux.com",
    "ctfile.com",
    "cowtransfer.com",
    "feimaoyun.com",
    "feimaoyun.cn",
    "cnki.net",
    "wanfangdata.com.cn",
    "vip.com",
    "vipshop.com",
    "jd.hk",
    "yixun.com",
    "suning.com",
    "suning.cn",
    "suningcloud.com",
    "gome.com.cn",
    "gomeplus.com",
    "dangdang.com",
    "amazon.cn",
    "z.cn",
    "ele.me",
    "elemecdn.com",
    "ele.me",
    "starbucks.com.cn",
    "mcdonalds.com.cn",
    "kfc.com.cn",
    "pizzahut.com.cn",
    "dominos.com.cn",
    "sf-express.com",
    "sf-express.cn",
    "zto.com",
    "ztocdn.com",
    "yto.net.cn",
    "ytocargo.com",
    "sto.cn",
    "best.com.cn",
    "jd-express.com",
    "jdwl.com",
    "deppon.com",
    "deppon.cn",
    "tnt.com.cn",
    "dhl.com.cn",
    "ups.com.cn",
    "fedex.com.cn",
    "ems.com.cn",
    "china-post.com.cn",
    "chinapost.com.cn",
    "10086.cn",
    "chinamobile.com",
    "10010.com",
    "chinaunicom.com",
    "189.cn",
    "chinatelecom.com.cn",
    "chinatelecom.cn",
    "mi.com",
    "xiaomi.com",
    "xiaomi.cn",
    "mi-img.com",
    "miui.com",
    "miwifi.com",
    "mifile.cn",
    "xiaomiyoupin.com",
    "youpin.cn",
    "huawei.com",
    "huawei.cn",
    "hicloud.com",
    "hihonor.com",
    "honor.cn",
    "vmall.com",
    "oppo.com",
    "oppo.cn",
    "oppomobile.com",
    "coloros.com",
    "realme.com",
    "realmebbs.com",
    "vivo.com",
    "vivo.cn",
    "vivo.com.cn",
    "bbk.com",
    "oneplus.com",
    "oneplus.cn",
    "oneplus.net",
    "oneplusbbs.com",
    "meizu.com",
    "meizu.cn",
    "flyme.cn",
    "flyme.com",
    "lenovo.com",
    "lenovo.com.cn",
    "lenovomm.cn",
    "zuk.com",
    "zuk.cn",
    "motorola.com.cn",
    "zte.com.cn",
    "zte.com",
    "nubia.com",
    "nubia.cn",
    "redmagic.com",
    "asus.com.cn",
    "asus.cn",
    "dell.com.cn",
    "hp.com.cn",
    "lenovopress.com",
    "thinkpad.com",
    "thinkpad.com.cn",
    // Apple China domains (for iMessage, iCloud in China)
    // Source: https://www.txthinking.com/talks/articles/brook-v20260101-en.article
    "apple.com.cn",
    "icloud.com.cn",
    "me.com.cn",
    "mzstatic.com",
    // Global Apple domains that need direct connection in China
    // Apple's push service does not allow proxying
    "apple.com",
    "icloud.com",
    "cdn-apple.com",
    "push-apple.com.akadns.net",
    "itunes-apple.com.akadns.net",
    "cdn-apple.com.akadns.net",
    "idms-apple.com.akadns.net",
    "apple.com.edgekey.net",
    "apple.com.edgekey.net.globalredir.akadns.net",
    "entrust.net",
    "digicert.com",
    "verisign.net",
    "akamaiedge.net",
    "akadns.net",
    "edgekey.net",
    "sony.com.cn",
    "samsung.com.cn",
    "samsung.cn",
    "lg.com.cn",
    "panasonic.cn",
    "philips.com.cn",
    "philips.cn",
    "bosch.com.cn",
    "siemens.com.cn",
    "electrolux.com.cn",
    "haier.com",
    "haier.net",
    "casarte.com.cn",
    "leader.com.cn",
    "midea.com",
    "midea.com.cn",
    "gree.com.cn",
    "gree.com",
    "auxgroup.com",
    "chigo.cn",
    "hisense.com",
    "hisense.cn",
    "tcl.com",
    "tcl.com.cn",
    "skyworth.com",
    "skyworth.cn",
    "changhong.com",
    "konka.com",
    "konka.com.cn",
    "joyoung.com",
    "joyoung.com.cn",
    "supor.com.cn",
    "robam.com",
    "fotile.com",
    "fotile.cn",
    "vatti.com.cn",
    "sacon.cn",
    "macro.com.cn",
    "vanward.com",
    "rinnai.com.cn",
    "noritz.com.cn",
    "ariston.com.cn",
    "buderus.cn",
    "viessmann.cn",
    "vaillant.com.cn",
    "sika.com.cn",
    "wilo.com.cn",
    "grundfos.cn",
    "danfoss.com.cn",
    "emerson.cn",
    "honeywell.com.cn",
    "schneider-electric.cn",
    "schneider-electric.com.cn",
    "abb.com.cn",
    "siemens.com.cn",
    "mitsubishielectric.com.cn",
    "panasonic.cn",
    "omron.com.cn",
    "yaskawa.com.cn",
    "fanuc.com.cn",
    "kuka.com.cn",
    "abb.cn",
    "kuka.cn",
    "yaskawa.cn",
    "fanuc.cn",
    "omron.cn",
    "mitsubishielectric.cn",
    "nidec.com.cn",
    "sany.com.cn",
    "zoomlion.com.cn",
    "xcmg.com",
    "xcmglift.com",
    "liugong.com",
    "liugong.cn",
    "sdlg.cn",
    "sdlg.com",
    "sdlg.cn",
    "sdlg.com.cn",
];

/// Common ad/tracking domains for blocking
/// Curated high-impact list covering major ad/tracking ecosystems.
/// Parent-domain matching is used, so root domains block subdomains automatically.
pub const AD_DOMAINS: &[&str] = &[
    // Google / Alphabet
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "tpc.googlesyndication.com",
    "partner.googleadservices.com",
    "ads.google.com",
    "ad.doubleclick.net",
    "pubads.g.doubleclick.net",
    "googletagservices.com",
    "googleoptimize.com",
    "app-measurement.com",
    "crashlytics.com",
    "googlerankings.com",
    "gstaticadssl.l.google.com",
    // Meta / Facebook
    "facebook.com/tr",
    "facebook.net",
    "connect.facebook.net",
    "graph.instagram.com",
    "pixel.facebook.com",
    "an.facebook.com",
    // Twitter / X
    "analytics.twitter.com",
    "ads-twitter.com",
    "static.ads-twitter.com",
    "ads.twitter.com",
    "advertising.twitter.com",
    // Amazon
    "amazon-adsystem.com",
    "amazon.advertising.com",
    "c.amazon-adsystem.com",
    "s.amazon-adsystem.com",
    "aax.amazon-adsystem.com",
    "aax-us-east.amazon-adsystem.com",
    "z-na.amazon-adsystem.com",
    "assoc-amazon.com",
    "ws-na.amazon-adsystem.com",
    // Microsoft
    "bat.bing.com",
    "clarity.ms",
    "ads.microsoft.com",
    "advertise.bingads.microsoft.com",
    "analytics.live.com",
    "msads.net",
    "msftads.com",
    // TikTok / ByteDance
    "ads.tiktok.com",
    "analytics.tiktok.com",
    "business.tiktok.com",
    "ads-sg.tiktok.com",
    "log.byteoversea.com",
    "pangolin-sdk-toutiao.com",
    // Programmatic / Ad-tech
    "openx.net",
    "rubiconproject.com",
    "pubmatic.com",
    "ads.pubmatic.com",
    "sharethrough.com",
    "adsrvr.org",
    "adsymptotic.com",
    "advertising.com",
    "adsystem.com",
    "adnxs.com",
    "33across.com",
    "adform.net",
    "criteo.com",
    "criteo.net",
    "casalemedia.com",
    "indexww.com",
    "sovrn.com",
    "lijit.com",
    "contextweb.com",
    "yieldmo.com",
    "teads.tv",
    "outbrain.com",
    "widgets.outbrain.com",
    "taboola.com",
    "cdn.taboola.com",
    "trc.taboola.com",
    "revcontent.com",
    "bidr.io",
    "bidswitch.net",
    "districtm.io",
    "gumgum.com",
    "media.net",
    "triplelift.com",
    "unrulymedia.com",
    "videoamp.com",
    "zemanta.com",
    // Analytics / Measurement
    "scorecardresearch.com",
    "scorecardresearch.com.edgekey.net",
    "comscore.com",
    "quantserve.com",
    "quantcount.com",
    "moatads.com",
    "moatpixel.com",
    "hotjar.com",
    "hotjar.io",
    "mixpanel.com",
    "amplitude.com",
    "segment.com",
    "segment.io",
    "heapanalytics.com",
    "kissmetrics.com",
    "optimizely.com",
    "visualwebsiteoptimizer.com",
    "luckyorange.com",
    "luckyorange.net",
    "clicktale.net",
    "fullstory.com",
    "logrocket.com",
    "newrelic.com",
    "nr-data.net",
    "datadoghq.com",
    "plausible.io",
    "statcounter.com",
    "yandex.ru",
    "metrica.yandex.com",
    "baidustatic.com",
    "hm.baidu.com",
    // Mobile / Gaming ad networks
    "admob.com",
    "googleadapis.l.google.com",
    "mopub.com",
    "ironsource.com",
    "unity3d.com",
    "unityads.unity3d.com",
    "applovin.com",
    "applvn.com",
    "chartboost.com",
    "adcolony.com",
    "vungle.com",
    "startapp.com",
    "inmobi.com",
    "tapjoy.com",
    "supersonicads.com",
    "fyber.com",
    "adgem.co",
    "pollfish.com",
    "ogury.co",
    "ogury.io",
    "mintegral.com",
    "rayjump.com",
    "zestads.com",
    "adtiming.com",
    // Smart TV / CTV
    "samba.tv",
    "innovid.com",
    "spotx.tv",
    "spotxchange.com",
    "tremorhub.com",
    "freewheel.tv",
    "tubemogul.com",
    "rokutunnel.com",
    "ads.roku.com",
    "samsungads.com",
    "lgads.tv",
    "rakutenadvertising.com",
    // Other major trackers / verification
    "adsafeprotected.com",
    "iasds.net",
    "doubleverify.com",
    "geoedge.be",
    "brandads.net",
    "flashtalking.com",
    "serving-sys.com",
    "dotomi.com",
    "mediaplex.com",
    "dpbolvw.net",
    "anrdoezrs.net",
    "kqzyfj.com",
    "jdoqocy.com",
    "tkqlhce.com",
    "linksynergy.com",
    "impact-ad.jp",
    "impactradius-event.com",
    "ad-juster.com",
    "adjust.com",
    "appsflyer.com",
    "kochava.com",
    "branch.io",
    "tenjin.io",
    "singular.net",
    "clevertap.com",
    "onesignal.com",
    "braze.com",
    "marketo.net",
    "klaviyo.com",
    "sumo.com",
    "sumome.com",
    "addthis.com",
    "addthisedge.com",
    "sharethis.com",
    "po.st",
    "omtrdc.net",
    "demdex.net",
    "everesttech.net",
    "turn.com",
    "exelator.com",
    "mathtag.com",
    "crwdcntrl.net",
    "agkn.com",
    "bluekai.com",
    "bkrtx.com",
    "neustar.biz",
    "webtrends.com",
    "siteimproveanalytics.com",
    "adobedtm.com",
    "typekit.net",
];

/// Domains that should ALWAYS go through VPN (never bypass, even if IP is in China ranges)
/// These are services that need to appear as coming from outside China
pub const FORCE_TUNNEL_DOMAINS: &[&str] = &[
    // Google services - must route through VPN
    "google.com",
    "www.google.com",
    "googleapis.com",
    "www.googleapis.com",
    "gstatic.com",
    "www.gstatic.com",
    "googleusercontent.com",
    "googlevideo.com",
    "ytimg.com",
    "youtube.com",
    "www.youtube.com",
    "youtu.be",
    "ggpht.com",
    "withgoogle.com",
    "googleadservices.com",
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "googlecommerce.com",
    "admob.com",
    "appspot.com",
    "cloud.google.com",
    "firebase.google.com",
    "firebaseio.com",
    // Meta/Facebook services
    "facebook.com",
    "www.facebook.com",
    "fbcdn.net",
    "instagram.com",
    "www.instagram.com",
    "cdninstagram.com",
    "whatsapp.com",
    "web.whatsapp.com",
    "messenger.com",
    "fb.com",
    // Twitter/X
    "twitter.com",
    "x.com",
    "twimg.com",
    "t.co",
    // Other blocked services
    "telegram.org",
    "t.me",
    "signal.org",
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "slack.com",
    "slack-edge.com",
    "github.com",
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "perplexity.ai",
    "bing.com",
    "duckduckgo.com",
    "wikipedia.org",
    "wikimedia.org",
    "medium.com",
    "reddit.com",
    "redd.it",
    "linkedin.com",
    "licdn.com",
    "quora.com",
    "pinterest.com",
    "pinimg.com",
    "tumblr.com",
    "flickr.com",
    "vimeo.com",
    "soundcloud.com",
    "spotify.com",
    "netflix.com",
    "hulu.com",
    "hbo.com",
    "max.com",
    "disney.com",
    "disneyplus.com",
    "espn.com",
    "bbc.com",
    "bbc.co.uk",
    "nytimes.com",
    "washingtonpost.com",
    "wsj.com",
    "bloomberg.com",
    "reuters.com",
    "apnews.com",
    "npr.org",
    "cnn.com",
    "foxnews.com",
];

/// Get China domains as a HashSet for fast lookup
#[allow(dead_code)]
pub fn get_china_domains() -> &'static HashSet<&'static str> {
    static DOMAINS: OnceLock<HashSet<&str>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        CHINA_DOMAINS.iter().copied().collect()
    })
}

/// Get ad domains as a HashSet for fast lookup
#[allow(dead_code)]
pub fn get_ad_domains() -> &'static HashSet<&'static str> {
    static DOMAINS: OnceLock<HashSet<&str>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        AD_DOMAINS.iter().copied().collect()
    })
}

/// Get domains for a country code
///
/// Returns domains for the specified country, or None if not supported.
/// Currently supported: "CN" (China)
///
/// # Arguments
/// * `country_code` - Two-letter ISO 3166 country code
///
/// # Returns
/// Option slice of domain strings, or None if country not supported
#[allow(dead_code)]
pub fn get_country_domains(country_code: &str) -> Option<&'static [&'static str]> {
    match country_code.to_uppercase().as_str() {
        "CN" => Some(CHINA_DOMAINS),
        // Add other countries here as needed
        _ => None,
    }
}

/// Check if a domain is in the China list
#[allow(dead_code)]
pub fn is_china_domain(domain: &str) -> bool {
    get_china_domains().contains(domain)
}

/// Check if a domain is in the ad blocking list
#[allow(dead_code)]
pub fn is_ad_domain(domain: &str) -> bool {
    get_ad_domains().contains(domain)
}

/// Check if a domain matches any pattern in the China list (including parent domains)
pub fn matches_china_domain(domain: &str) -> bool {
    let china_domains = get_china_domains();
    
    // Direct match
    if china_domains.contains(domain) {
        return true;
    }
    
    // Check parent domains
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if china_domains.contains(parent.as_str()) {
            return true;
        }
    }
    
    false
}

/// Check if a domain matches any pattern in the ad list (including parent domains)
#[allow(dead_code)]
pub fn matches_ad_domain(domain: &str) -> bool {
    let ad_domains = get_ad_domains();
    
    // Direct match
    if ad_domains.contains(domain) {
        return true;
    }
    
    // Check parent domains
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if ad_domains.contains(parent.as_str()) {
            return true;
        }
    }
    
    false
}

/// Get force tunnel domains as a HashSet for fast lookup
pub fn get_force_tunnel_domains() -> &'static HashSet<&'static str> {
    static DOMAINS: OnceLock<HashSet<&str>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        FORCE_TUNNEL_DOMAINS.iter().copied().collect()
    })
}

/// Check if a domain should always go through VPN (force tunnel)
/// This overrides any IP-based bypass decisions
pub fn matches_force_tunnel_domain(domain: &str) -> bool {
    let force_domains = get_force_tunnel_domains();
    
    // Direct match
    if force_domains.contains(domain) {
        return true;
    }
    
    // Check parent domains
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if force_domains.contains(parent.as_str()) {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_china_domain_matching() {
        assert!(matches_china_domain("www.baidu.com"));
        assert!(matches_china_domain("baidu.com"));
        assert!(matches_china_domain("api.taobao.com"));
        assert!(!matches_china_domain("google.com"));
    }

    #[test]
    fn test_ad_domain_matching() {
        assert!(matches_ad_domain("doubleclick.net"));
        assert!(matches_ad_domain("googleadservices.com"));
        assert!(!matches_ad_domain("example.com"));
    }
}
