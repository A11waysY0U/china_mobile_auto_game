import argparse
import base64
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from urllib.parse import quote


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 "
    "Mobile/15E148 Safari/604.1"
)

JS_ENCODE_URI_COMPONENT_SAFE = "-_.!~*'()"
DFM_MAPPING = "t6KJCZa5pDdQ9khoEM3Tj70fbP2eLSyc4BrsYugARqFIw1mzlGNVXOHiWvxUn8"
COMMON_SECOND_LEVEL_SUFFIXES = {"ac", "co", "com", "edu", "gov", "net", "org"}


def js_like_quote(value: str) -> str:
    return quote(value, safe=JS_ENCODE_URI_COMPONENT_SAFE)


def base64_encode_utf8(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def dfmapping(value: str) -> str:
    reverse_map = {
        DFM_MAPPING[index]: DFM_MAPPING[len(DFM_MAPPING) - 1 - index]
        for index in range(len(DFM_MAPPING))
    }
    return "".join(reverse_map.get(char, char) for char in value)


def user_encrypt(value: str) -> str:
    return "dfm-enc-" + dfmapping(value)


def crypto_random() -> float:
    return secrets.randbits(32) / float(2**32)


def js_like_random_hex_fraction(hex_digits: int = 13) -> str:
    return "0" + secrets.token_hex((hex_digits + 1) // 2)[:hex_digits]


def timing_hex() -> str:
    millis = int(time.time() * 1000)
    counter = 0
    while int(time.time() * 1000) == millis:
        counter += 1
    return f"{millis:x}{counter:x}"


def ua_hash_hex(user_agent: str) -> str:
    bucket = []
    acc = 0
    for char in user_agent:
        bucket.insert(0, ord(char) & 0xFF)
        if len(bucket) >= 4:
            chunk = 0
            for index, byte in enumerate(bucket):
                chunk |= byte << (8 * index)
            acc = (acc ^ chunk) & 0xFFFFFFFF
            bucket = []
    if bucket:
        chunk = 0
        for index, byte in enumerate(bucket):
            chunk |= byte << (8 * index)
        acc = (acc ^ chunk) & 0xFFFFFFFF
    signed = acc if acc < 0x80000000 else acc - 0x100000000
    return format(signed, "x")


def screen_hex(width: int, height: int) -> str:
    product = width * height
    digits = str(product)
    if re.search(r"\d{5,}", digits):
        return format(product, "x")
    return str(int(31242 * crypto_random())).replace(".", "")[:8]


def generate_distinct_id(
    user_agent: str = DEFAULT_USER_AGENT,
    screen_width: int = 390,
    screen_height: int = 844,
) -> str:
    return (
        f"{timing_hex()}-"
        f"{js_like_random_hex_fraction()}-"
        f"{ua_hash_hex(user_agent)}-"
        f"{screen_hex(screen_width, screen_height)}-"
        f"{timing_hex()}"
    )


def stringify_minified(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def encode_identities(identities: dict) -> str:
    return base64_encode_utf8(stringify_minified(identities))


def derive_cookie_domain(host: str) -> str:
    host = (host or "").strip().lower()
    if not host or host in {"localhost", "127.0.0.1"}:
        return ""
    if re.fullmatch(r"(\d+\.)+\d+", host):
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return ""
    if (
        len(parts) >= 3
        and len(parts[-1]) == 2
        and parts[-2] in COMMON_SECOND_LEVEL_SUFFIXES
    ):
        return "." + ".".join(parts[-3:])
    return "." + ".".join(parts[-2:])


def get_main_cookie_name(sdk_id: str = "", cross_subdomain: bool = True, host: str = "") -> str:
    if cross_subdomain:
        return f"sensorsdata2015jssdkcross{sdk_id}"
    if host:
        return f"sa_jssdk_2015_{sdk_id}{host.replace('.', '_')}"
    return f"sa_jssdk_2015_root{sdk_id}"


def get_new_user_cookie_name(sdk_id: str = "", cross_subdomain: bool = True, host: str = "") -> str:
    if cross_subdomain:
        return f"sajssdk_2015_cross_{sdk_id}new_user"
    if host:
        return f"sajssdk_2015_{sdk_id}new_user_{host.replace('.', '_')}"
    return f"sajssdk_2015_root_{sdk_id}new_user"


def seconds_until_end_of_day(now: datetime | None = None) -> int:
    now = now or datetime.now().astimezone()
    end_of_day = now.replace(hour=23, minute=59, second=59, microsecond=0)
    return max(1, int((end_of_day - now).total_seconds()))


def cookie_expires(days: float | int) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(days=float(days))
    return format_datetime(expires_at, usegmt=True)


def cookie_expires_seconds(seconds: int) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(seconds))
    return format_datetime(expires_at, usegmt=True)


def build_state(
    distinct_id: str,
    latest_traffic_source_type: str = "直接流量",
    latest_search_keyword: str = "未取到值_直接打开",
    latest_referrer: str = "",
) -> dict:
    return {
        "distinct_id": distinct_id,
        "first_id": "",
        "props": {
            "$latest_traffic_source_type": latest_traffic_source_type,
            "$latest_search_keyword": latest_search_keyword,
            "$latest_referrer": latest_referrer,
        },
        "identities": encode_identities({"$identity_cookie_id": distinct_id}),
        "history_login_id": {"name": "", "value": ""},
    }


def encode_main_cookie_value(state: dict, encrypt_cookie: bool = False) -> str:
    value = stringify_minified(state)
    if encrypt_cookie:
        value = user_encrypt(value)
    return js_like_quote(value)


@dataclass
class CookieBundle:
    distinct_id: str
    main_cookie_name: str
    main_cookie_value: str
    new_user_cookie_name: str
    new_user_cookie_value: str
    cookie_domain: str
    main_cookie_header: str
    new_user_cookie_header: str
    cookie_header: str


def build_cookie_bundle(
    host: str,
    user_agent: str = DEFAULT_USER_AGENT,
    screen_width: int = 390,
    screen_height: int = 844,
    sdk_id: str = "",
    cross_subdomain: bool = True,
    encrypt_cookie: bool = False,
    latest_traffic_source_type: str = "直接流量",
    latest_search_keyword: str = "未取到值_直接打开",
    latest_referrer: str = "",
) -> CookieBundle:
    distinct_id = generate_distinct_id(
        user_agent=user_agent,
        screen_width=screen_width,
        screen_height=screen_height,
    )
    state = build_state(
        distinct_id=distinct_id,
        latest_traffic_source_type=latest_traffic_source_type,
        latest_search_keyword=latest_search_keyword,
        latest_referrer=latest_referrer,
    )
    main_cookie_name = get_main_cookie_name(
        sdk_id=sdk_id,
        cross_subdomain=cross_subdomain,
        host=host,
    )
    new_user_cookie_name = get_new_user_cookie_name(
        sdk_id=sdk_id,
        cross_subdomain=cross_subdomain,
        host=host,
    )
    cookie_domain = derive_cookie_domain(host) if cross_subdomain else ""
    domain_attr = f"; Domain={cookie_domain}" if cookie_domain else ""
    main_cookie_value = encode_main_cookie_value(state, encrypt_cookie=encrypt_cookie)
    new_user_cookie_value = "1"

    main_cookie_header = (
        f"{main_cookie_name}={main_cookie_value}; "
        f"Expires={cookie_expires(360)}; Path=/{domain_attr}"
    )
    new_user_cookie_header = (
        f"{new_user_cookie_name}={new_user_cookie_value}; "
        f"Expires={cookie_expires_seconds(seconds_until_end_of_day())}; "
        f"Path=/{domain_attr}"
    )

    return CookieBundle(
        distinct_id=distinct_id,
        main_cookie_name=main_cookie_name,
        main_cookie_value=main_cookie_value,
        new_user_cookie_name=new_user_cookie_name,
        new_user_cookie_value=new_user_cookie_value,
        cookie_domain=cookie_domain,
        main_cookie_header=main_cookie_header,
        new_user_cookie_header=new_user_cookie_header,
        cookie_header=(
            f"{new_user_cookie_name}={new_user_cookie_value}; "
            f"{main_cookie_name}={main_cookie_value}"
        ),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Sensors Analytics style cookies from 3.js."
    )
    parser.add_argument("--host", default="wap.fj.10086.cn")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--screen-width", type=int, default=390)
    parser.add_argument("--screen-height", type=int, default=844)
    parser.add_argument("--sdk-id", default="")
    parser.add_argument("--latest-traffic-source-type", default="直接流量")
    parser.add_argument("--latest-search-keyword", default="未取到值_直接打开")
    parser.add_argument("--latest-referrer", default="")
    parser.add_argument(
        "--no-cross-subdomain",
        action="store_true",
        help="Use single-domain cookie names instead of cross-domain names.",
    )
    parser.add_argument(
        "--encrypt-cookie",
        action="store_true",
        help="Apply the optional dfm-enc- userEncrypt transform.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bundle = build_cookie_bundle(
        host=args.host,
        user_agent=args.user_agent,
        screen_width=args.screen_width,
        screen_height=args.screen_height,
        sdk_id=args.sdk_id,
        cross_subdomain=not args.no_cross_subdomain,
        encrypt_cookie=args.encrypt_cookie,
        latest_traffic_source_type=args.latest_traffic_source_type,
        latest_search_keyword=args.latest_search_keyword,
        latest_referrer=args.latest_referrer,
    )

    print("distinct_id:")
    print(bundle.distinct_id)
    print()
    print("cookie header:")
    print(bundle.cookie_header)
    print()
    print("set-cookie:")
    print(bundle.new_user_cookie_header)
    print(bundle.main_cookie_header)


if __name__ == "__main__":
    main()
