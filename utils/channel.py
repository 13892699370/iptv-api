# utils/channel.py - 修复后的版本 (集成快速连接检查逻辑)

import asyncio
import base64
import gzip
import json
import logging
import math
import os
import pickle
import re
from collections import defaultdict
from logging import INFO

from bs4 import NavigableString

import utils.constants as constants
from updates.epg.tools import write_to_xml, compress_to_gz
from utils.alias import Alias
from utils.config import config
from utils.db import get_db_connection, return_db_connection
from utils.ip_checker import IPChecker
from utils.speed import (
    get_speed,
    get_speed_result,
    get_sort_result,
    check_ffmpeg_installed_status,
    # 💥 导入新增的快速连接检查函数
    quick_check_url_connection 
)
from utils.tools import (
    format_name,
    get_name_url,
    check_url_by_keywords,
    get_total_urls,
    add_url_info,
    resource_path,
    get_urls_from_file,
    get_name_urls_from_file,
    get_logger,
    get_datetime_now,
    get_url_host,
    check_ipv_type_match,
    get_ip_address,
    convert_to_m3u,
    custom_print,
    get_name_uri_from_dir,
    get_resolution_value
)
from utils.types import ChannelData, OriginType, CategoryChannelData, TestResult

channel_alias = Alias()
ip_checker = IPChecker()
frozen_channels = set()
location_list = config.location
isp_list = config.isp
max_delay = config.speed_test_timeout * 1000
min_resolution_value = config.min_resolution_value
open_history = config.open_history
open_local = config.open_local
open_rtmp = config.open_rtmp
retain_origin = ["whitelist", "live", "hls"]


# --- (其余函数保持不变，省略以保持简洁，直到 test_speed) ---

# 注意：为了完整性，您需要确保将我提供的完整代码（包括这些省略的部分）替换掉您现有的 utils/channel.py

def format_channel_data(url: str, origin: OriginType) -> ChannelData:
# ... (保持不变) ...
    url_partition = url.partition("$")
    url = url_partition[0]
    info = url_partition[2]
    if info and info.startswith("!"):
        origin = "whitelist"
        info = info[1:]
    return {
        "id": hash(url),
        "url": url,
        "host": get_url_host(url),
        "origin": origin,
        "ipv_type": None,
        "extra_info": info
    }

def check_channel_need_frozen(info: TestResult) -> bool:
# ... (保持不变) ...
    delay = info.get("delay", 0)
    if (delay == -1 or delay > max_delay) or info.get("speed", 0) == 0:
        return True
    if info.get("resolution"):
        if get_resolution_value(info["resolution"]) < min_resolution_value:
            return True
    return False

def get_channel_data_from_file(channels, file, whitelist, blacklist,
                               local_data=None, live_data=None, hls_data=None) -> CategoryChannelData:
# ... (保持不变) ...
    current_category = ""

    for line in file:
        line = line.strip()
        if "#genre#" in line:
            current_category = line.partition(",")[0]
        else:
            name_url = get_name_url(
                line, pattern=constants.demo_txt_pattern, check_url=False
            )
            if name_url and name_url[0]:
                name = name_url[0]["name"]
                url = name_url[0]["url"]
                category_dict = channels[current_category]
                if name not in category_dict:
                    category_dict[name] = []
                    if name in whitelist:
                        for whitelist_url in whitelist[name]:
                            category_dict[name].append(format_channel_data(whitelist_url, "whitelist"))
                    if live_data and name in live_data:
                        for live_url in live_data[name]:
                            category_dict[name].append(format_channel_data(live_url, "live"))
                    if hls_data and name in hls_data:
                        for hls_url in hls_data[name]:
                            category_dict[name].append(format_channel_data(hls_url, "hls"))
                    if open_local and local_data:
                        alias_names = channel_alias.get(name)
                        alias_names.update([name, format_name(name)])
                        for alias_name in alias_names:
                            if alias_name in local_data:
                                for local_url in local_data[alias_name]:
                                    if not check_url_by_keywords(local_url, blacklist):
                                        category_dict[name].append(format_channel_data(local_url, "local"))
                            elif alias_name.startswith("re:"):
                                raw_pattern = alias_name[3:]
                                try:
                                    pattern = re.compile(raw_pattern)
                                    for local_name in local_data:
                                        if re.match(pattern, local_name):
                                            for local_url in local_data[local_name]:
                                                if not check_url_by_keywords(local_url, blacklist):
                                                    category_dict[name].append(format_channel_data(local_url, "local"))
                                except re.error:
                                    pass
                if open_local and url:
                    if not check_url_by_keywords(url, blacklist):
                        category_dict[name].append(format_channel_data(url, "local"))
    return channels

def get_channel_items() -> CategoryChannelData:
# ... (保持不变) ...
    user_source_file = resource_path(config.source_file)
    channels = defaultdict(lambda: defaultdict(list))
    live_data = None
    hls_data = None
    if config.open_rtmp:
        live_data = get_name_uri_from_dir(constants.live_path)
        hls_data = get_name_uri_from_dir(constants.hls_path)
    local_data = get_name_urls_from_file(config.local_file)
    whitelist = get_name_urls_from_file(constants.whitelist_path)
    blacklist = get_urls_from_file(constants.blacklist_path, pattern_search=False)
    whitelist_len = len(list(whitelist.keys()))
    if whitelist_len:
        print(f"Found {whitelist_len} channel in whitelist")

    if os.path.exists(user_source_file):
        with open(user_source_file, "r", encoding="utf-8") as file:
            channels = get_channel_data_from_file(
                channels, file, whitelist, blacklist, local_data, live_data, hls_data
            )

    if config.open_history:
        if os.path.exists(constants.cache_path):
            try:
                with gzip.open(constants.cache_path, "rb") as file:
                    old_result = pickle.load(file)
                    for cate, data in channels.items():
                        if cate in old_result:
                            for name, info_list in data.items():
                                urls = [
                                    url
                                    for item in info_list
                                    if (url := item["url"])
                                ]
                                if name in old_result[cate]:
                                    channel_data = channels[cate][name]
                                    for info in old_result[cate][name]:
                                        if info:
                                            info_url = info["url"]
                                            try:
                                                if info["origin"] in retain_origin or check_url_by_keywords(info_url,
                                                                                                           blacklist):
                                                    continue
                                                if check_channel_need_frozen(info):
                                                    frozen_channels.add(info_url)
                                                    continue
                                            except:
                                                pass
                                            if info_url not in urls:
                                                channel_data.append(info)

                                    if not channel_data:
                                        for info in old_result[cate][name]:
                                            old_result_url = info["url"]
                                            if info and info[
                                                "origin"] not in retain_origin and old_result_url not in urls and not check_url_by_keywords(
                                                old_result_url, blacklist):
                                                channel_data.append(info)
                                                frozen_channels.discard(old_result_url)

                                    channel_urls = {d["url"] for d in channel_data}
                                    if channel_urls.issubset(frozen_channels):
                                        frozen_channels.difference_update(channel_urls)

            except Exception as e:
                print(f"Error loading cache file: {e}")
                pass
    return channels

def format_channel_name(name):
# ... (保持不变) ...
    """
    Format the channel name with sub and replace and lower
    """
    return channel_alias.get_primary(name)


def channel_name_is_equal(name1, name2):
# ... (保持不变) ...
    """
    Check if the channel name is equal
    """
    name1_format = format_channel_name(name1)
    name2_format = format_channel_name(name2)
    return name1_format == name2_format

# ... (省略中间函数直到 test_speed) ...

def get_channel_results_by_name(name, data):
# ... (保持不变) ...
    """
    Get channel results from data by name
    """
    format_name = format_channel_name(name)
    results = data.get(format_name, [])
    return results

def get_element_child_text_list(element, child_name):
# ... (保持不变) ...
    """
    Get the child text of the element
    """
    text_list = []
    children = element.find_all(child_name)
    if children:
        for child in children:
            text = child.get_text(strip=True)
            if text:
                text_list.append(text)
    return text_list

def get_multicast_ip_list(urls):
# ... (保持不变) ...
    """
    Get the multicast ip list from urls
    """
    ip_list = []
    for url in urls:
        pattern = r"rtp://((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?)"
        matcher = re.search(pattern, url)
        if matcher:
            ip_list.append(matcher.group(1))
    return ip_list

def get_channel_multicast_region_ip_list(result, channel_region, channel_type):
# ... (保持不变) ...
    """
    Get the channel multicast region ip list by region and type from result
    """
    return [
        ip
        for result_region, result_obj in result.items()
        if result_region in channel_region
        for url_type, urls in result_obj.items()
        if url_type in channel_type
        for ip in get_multicast_ip_list(urls)
    ]

def get_channel_multicast_name_region_type_result(result, names):
# ... (保持不变) ...
    """
    Get the multicast name and region and type result by names from result
    """
    name_region_type_result = {}
    for name in names:
        data = result.get(name)
        if data:
            name_region_type_result[name] = data
    return name_region_type_result

def get_channel_multicast_region_type_list(result):
# ... (保持不变) ...
    """
    Get the channel multicast region type list from result
    """
    region_list = config.multicast_region_list
    region_type_list = {
        (region, r_type)
        for region_type in result.values()
        for region, types in region_type.items()
        if "all" in region_list
            or "ALL" in region_list
            or "全部" in region_list
            or region in region_list
        for r_type in types
    }
    return list(region_type_list)

def get_channel_multicast_result(result, search_result):
# ... (保持不变) ...
    """
    Get the channel multicast info result by result and search result
    """
    info_result = {}
    multicast_name = constants.origin_map.get("multicast", "")
    open_url_info = config.open_url_info
    for name, result_obj in result.items():
        info_list = []
        for result_region, result_types in result_obj.items():
            if result_region not in search_result:
                continue
            sr_region = search_result[result_region]
            for result_type, result_type_urls in result_types.items():
                if result_type not in sr_region:
                    continue
                ips = get_multicast_ip_list(result_type_urls)
                if not ips:
                    continue
                for item in sr_region[result_type]:
                    host = item.get("url")
                    if not host:
                        continue
                    for ip in ips:
                        total_url = f"http://{host}/rtp/{ip}"
                        info_list.append({
                            "url": add_url_info(total_url,
                                                f"{result_region}{result_type}{multicast_name}") if open_url_info else total_url,
                            "date": item.get("date")
                        })
        info_result[name] = info_list
    return info_result

def get_results_from_soup(soup, name):
# ... (保持不变) ...
    """
    Get the results from the soup
    """
    results = []
    if not soup.descendants:
        return results
    for element in soup.descendants:
        if isinstance(element, NavigableString):
            text = element.get_text(strip=True)
            url = get_channel_url(text)
            if url and not any(item[0] == url for item in results):
                url_element = soup.find(lambda tag: tag.get_text(strip=True) == url)
                if url_element:
                    name_element = url_element.find_previous_sibling()
                    if name_element:
                        channel_name = name_element.get_text(strip=True)
                        if channel_name_is_equal(name, channel_name):
                            info_element = url_element.find_next_sibling()
                            date, resolution = get_channel_info(
                                info_element.get_text(strip=True)
                            )
                            results.append({
                                "url": url,
                                "date": date,
                                "resolution": resolution,
                            })
    return results

def get_results_from_multicast_soup(soup, hotel=False):
# ... (保持不变) ...
    """
    Get the results from the multicast soup
    """
    results = []
    if not soup.descendants:
        return results
    for element in soup.descendants:
        if isinstance(element, NavigableString):
            text = element.strip()
            if "失效" in text:
                continue
            url = get_channel_url(text)
            if url and not any(item["url"] == url for item in results):
                url_element = soup.find(lambda tag: tag.get_text(strip=True) == url)
                if not url_element:
                    continue
                parent_element = url_element.find_parent()
                info_element = parent_element.find_all(recursive=False)[-1]
                if not info_element:
                    continue
                info_text = info_element.get_text(strip=True)
                if "上线" in info_text and " " in info_text:
                    date, region, channel_type = get_multicast_channel_info(info_text)
                    if hotel and "酒店" not in region:
                        continue
                    results.append(
                        {
                            "url": url,
                            "date": date,
                            "region": region,
                            "type": channel_type,
                        }
                    )
    return results

def get_results_from_soup_requests(soup, name):
# ... (保持不变) ...
    """
    Get the results from the soup by requests
    """
    results = []
    elements = soup.find_all("div", class_="resultplus") if soup else []
    for element in elements:
        name_element = element.find("div", class_="channel")
        if name_element:
            channel_name = name_element.get_text(strip=True)
            if channel_name_is_equal(name, channel_name):
                text_list = get_element_child_text_list(element, "div")
                url = date = resolution = None
                for text in text_list:
                    text_url = get_channel_url(text)
                    if text_url:
                        url = text_url
                    if " " in text:
                        text_info = get_channel_info(text)
                        date, resolution = text_info
                if url:
                    results.append({
                        "url": url,
                        "date": date,
                        "resolution": resolution,
                    })
    return results

def get_results_from_multicast_soup_requests(soup, hotel=False):
# ... (保持不变) ...
    """
    Get the results from the multicast soup by requests
    """
    results = []
    if not soup:
        return results

    elements = soup.find_all("div", class_="result")
    for element in elements:
        name_element = element.find("div", class_="channel")
        if not name_element:
            continue

        text_list = get_element_child_text_list(element, "div")
        url, date, region, channel_type = None, None, None, None
        valid = True

        for text in text_list:
            if "失效" in text:
                valid = False
                break

            text_url = get_channel_url(text)
            if text_url:
                url = text_url

            if url and "上线" in text and " " in text:
                date, region, channel_type = get_multicast_channel_info(text)

        if url and valid:
            if hotel and "酒店" not in region:
                continue
            results.append({"url": url, "date": date, "region": region, "type": channel_type})

    return results

def get_channel_url(text):
# ... (保持不变) ...
    """
    Get the url from text
    """
    url = None
    url_search = constants.url_pattern.search(text)
    if url_search:
        url = url_search.group()
    return url

def get_channel_info(text):
# ... (保持不变) ...
    """
    Get the channel info from text
    """
    date, resolution = None, None
    if text:
        date, resolution = (
            (text.partition(" ")[0] if text.partition(" ")[0] else None),
            (
                text.partition(" ")[2].partition("•")[2]
                if text.partition(" ")[2].partition("•")[2]
                else None
            ),
        )
    return date, resolution

def get_multicast_channel_info(text):
# ... (保持不变) ...
    """
    Get the multicast channel info from text
    """
    date, region, channel_type = None, None, None
    if text:
        text_split = text.split(" ")
        filtered_data = list(filter(lambda x: x.strip() != "", text_split))
        if filtered_data and len(filtered_data) == 4:
            date = filtered_data[0]
            region = filtered_data[2]
            channel_type = filtered_data[3]
    return date, region, channel_type


def init_info_data(data: dict, category: str, name: str) -> None:
# ... (保持不变) ...
    """
    Initialize channel info data structure if not exists
    """
    data.setdefault(category, {}).setdefault(name, [])


def append_data_to_info_data(
        info_data: dict,
        category: str,
        name: str,
        data: list,
        origin: str = None,
        whitelist: list = None,
        blacklist: list = None,
        ipv_type_data: dict = None
) -> None:
# ... (保持不变) ...
    """
    Append channel data to total info data with deduplication and validation

    Args:
        info_data: The main data structure to update
        category: Category key for the data
        name: Name key within the category
        data: List of channel items to process
        origin: Default origin for items
        whitelist: List of whitelist keywords
        blacklist: List of blacklist keywords
        ipv_type_data: Dictionary to cache IP type information
    """
    init_info_data(info_data, category, name)

    channel_list = info_data[category][name]
    existing_urls = {info["url"] for info in channel_list if "url" in info}

    for item in data:
        try:
            channel_id = item.get("id") or hash(item["url"])
            url = item["url"]
            host = item.get("host") or get_url_host(url)
            date = item.get("date")
            delay = item.get("delay")
            speed = item.get("speed")
            resolution = item.get("resolution")
            url_origin = item.get("origin", origin)
            ipv_type = item.get("ipv_type")
            location = item.get("location")
            isp = item.get("isp")
            headers = item.get("headers")
            catchup = item.get("catchup")
            extra_info = item.get("extra_info", "")

            if not url or url in existing_urls:
                continue

            if url_origin != "whitelist" and whitelist and check_url_by_keywords(url, whitelist):
                url_origin = "whitelist"

            if not url_origin:
                continue

            if url_origin not in retain_origin:
                if url in frozen_channels or blacklist and check_url_by_keywords(url, blacklist):
                    continue

                if not ipv_type:
                    if ipv_type_data and host in ipv_type_data:
                        ipv_type = ipv_type_data[host]
                    else:
                        ipv_type = ip_checker.get_ipv_type(url)
                        if ipv_type_data is not None:
                            ipv_type_data[host] = ipv_type

                if not check_ipv_type_match(ipv_type):
                    continue

                if not location or not isp:
                    ip = ip_checker.get_ip(url)
                    if ip:
                        location, isp = ip_checker.find_map(ip)

                if location and location_list and not any(item in location for item in location_list):
                    continue

                if isp and isp_list and not any(item in isp for item in isp_list):
                    continue
            channel_list.append({
                "id": channel_id,
                "url": url,
                "host": host,
                "date": date,
                "delay": delay,
                "speed": speed,
                "resolution": resolution,
                "origin": url_origin,
                "ipv_type": ipv_type,
                "location": location,
                "isp": isp,
                "headers": headers,
                "catchup": catchup,
                "extra_info": extra_info
            })
            existing_urls.add(url)

        except Exception as e:
            print(f"Error processing channel data: {e}")
            continue


def get_origin_method_name(method):
# ... (保持不变) ...
    """
    Get the origin method name
    """
    return "hotel" if method.startswith("hotel_") else method


def append_old_data_to_info_data(info_data, cate, name, data, whitelist=None, blacklist=None, ipv_type_data=None):
# ... (保持不变) ...
    """
    Append old existed channel data to total info data
    """

    def append_and_print(items, origin, label):
        if items:
            append_data_to_info_data(
                info_data, cate, name, items,
                origin=origin if origin else None,
                whitelist=whitelist,
                blacklist=blacklist,
                ipv_type_data=ipv_type_data
            )
        print(f"{label}: {len(items)}", end=", ")

    whitelist_data = [item for item in data if item["origin"] == "whitelist"]
    append_and_print(whitelist_data, "whitelist", "Whitelist")

    if open_local:
        local_data = [item for item in data if item["origin"] == "local"]
        append_and_print(local_data, "local", "Local")

    if open_rtmp:
        rtmp_data = [item for item in data if item["origin"] in ["live", "hls"]]
        append_and_print(rtmp_data, None, "RTMP")
        live_len = sum(1 for item in rtmp_data if item["origin"] == "live")
        hls_len = sum(1 for item in rtmp_data if item["origin"] == "hls")
        print(f"Live: {live_len}, HLS: {hls_len}", end=", ")

    if open_history:
        history_data = [item for item in data if item["origin"] not in ["live", "hls", "local", "whitelist"]]
        append_and_print(history_data, None, "History")


def print_channel_number(data: CategoryChannelData, cate: str, name: str):
# ... (保持不变) ...
    """
    Print channel number
    """
    channel_list = data.get(cate, {}).get(name, [])
    print("IPv4:", len([channel for channel in channel_list if channel["ipv_type"] == "ipv4"]), end=", ")
    print("IPv6:", len([channel for channel in channel_list if channel["ipv_type"] == "ipv6"]), end=", ")
    print(
        "Total:",
        len(channel_list),
    )


def append_total_data(
        items,
        data,
        hotel_fofa_result=None,
        multicast_result=None,
        hotel_foodie_result=None,
        subscribe_result=None,
        online_search_result=None,
):
# ... (保持不变) ...
    """
    Append all method data to total info data
    """
    total_result = [
        ("hotel_fofa", hotel_fofa_result),
        ("multicast", multicast_result),
        ("hotel_foodie", hotel_foodie_result),
        ("subscribe", subscribe_result),
        ("online_search", online_search_result),
    ]
    whitelist = get_urls_from_file(constants.whitelist_path)
    blacklist = get_urls_from_file(constants.blacklist_path, pattern_search=False)
    url_hosts_ipv_type = {}
    for obj in data.values():
        for value_list in obj.values():
            for value in value_list:
                if value_ipv_type := value.get("ipv_type", None):
                    url_hosts_ipv_type[get_url_host(value["url"])] = value_ipv_type
    for cate, channel_obj in items:
        for name, old_info_list in channel_obj.items():
            print(f"{name}:", end=" ")
            if old_info_list:
                append_old_data_to_info_data(data, cate, name, old_info_list, whitelist=whitelist, blacklist=blacklist,
                                             ipv_type_data=url_hosts_ipv_type)
            for method, result in total_result:
                if config.open_method[method]:
                    origin_method = get_origin_method_name(method)
                    if not origin_method:
                        continue
                    name_results = get_channel_results_by_name(name, result)
                    append_data_to_info_data(
                        data, cate, name, name_results, origin=origin_method, whitelist=whitelist, blacklist=blacklist,
                        ipv_type_data=url_hosts_ipv_type
                    )
                    print(f"{method.capitalize()}:", len(name_results), end=", ")
            print_channel_number(data, cate, name)


async def test_speed(data, ipv6=False, callback=None):
    """
    Test speed of channel data - Integrated quick check logic.
    """
    ipv6_proxy_url = None if (not config.open_ipv6 or ipv6) else constants.ipv6_proxy
    open_headers = config.open_headers
    get_resolution = config.open_filter_resolution and check_ffmpeg_installed_status()
    semaphore = asyncio.Semaphore(config.speed_test_limit)
    logger = get_logger(constants.speed_test_log_path, level=INFO, init=True)

    # 1. 准备数据和任务列表
    channels_to_test = []
    
    # 用于聚合所有结果 (包括快速检查失败的)
    grouped_results = defaultdict(lambda: defaultdict(list))
    
    for cate, channel_obj in data.items():
        for name, info_list in channel_obj.items():
            for info in info_list:
                # 跳过已冻结的
                if info["url"] in frozen_channels:
                    continue 
                info['name'] = name
                channels_to_test.append((cate, name, info))
                
    # 2. 💥 启动快速连接检查任务 (粗筛死链接)
    print("--- Starting Quick Connection Check (filtering dead links)... ---")
    
    quick_check_tasks = [
        asyncio.create_task(quick_check_url_connection(info)) 
        for _, _, info in channels_to_test
    ]
    
    # 并发执行快速检查
    quick_check_results = await asyncio.gather(*quick_check_tasks, return_exceptions=True)

    # 3. 筛选出连接正常的频道进行正式测速
    full_test_tasks = []
    
    for info_tuple, is_valid in zip(channels_to_test, quick_check_results):
        cate, name, info = info_tuple
        
        # 检查结果是否是布尔值 True (连接成功)
        if is_valid is True:
             # 连接成功，加入到正式测速队列
             async with semaphore: # 应用速率限制
                 headers = (open_headers and info.get("headers")) or None
                 # 创建完整的 get_speed 任务
                 task = asyncio.create_task(
                    get_speed(
                        info,
                        headers=headers,
                        ipv6_proxy=ipv6_proxy_url,
                        filter_resolution=get_resolution,
                        logger=logger,
                        callback=callback,
                    )
                 )
                 full_test_tasks.append(task)
                 # 用于映射结果到原始频道信息
                 full_test_tasks_map[task] = (cate, name, info) 
                 
        else:
            # 连接失败 (False 或 Exception)，直接记录为测速失败
            result = {'speed': 0, 'delay': -1, 'resolution': info['resolution'] or None}
            grouped_results[cate][name].append({**info, **result})
            # 更新进度条 (虽然没有测速，但占用了资源，应更新)
            if callback: callback()


    print(f"--- Quick Check Complete. {len(full_test_tasks)} channels remaining for full speed test. ---")

    # 4. 执行完整的测速任务
    full_test_results = await asyncio.gather(*full_test_tasks, return_exceptions=True)

    # 5. 聚合完整的测速结果
    for task, result in zip(full_test_tasks, full_test_results):
        cate, name, info = full_test_tasks_map[task]
        
        # 确保结果是字典类型
        if not isinstance(result, dict):
             result = {'speed': 0, 'delay': -1, 'resolution': info['resolution'] or None}
             
        grouped_results[cate][name].append({**info, **result})

    logger.handlers.clear()
    
    # 返回聚合了快速检查失败和完整测速成功的最终结果
    return grouped_results


def sort_channel_result(channel_data, result=None, filter_host=False, ipv6_support=True):
# ... (保持不变) ...
    """
    Sort channel result
    """
    channel_result = defaultdict(lambda: defaultdict(list))
    logger = get_logger(constants.result_log_path, level=INFO, init=True)
    for cate, obj in channel_data.items():
        for name, values in obj.items():
            if not values:
                continue
            whitelist_result = []
            test_result = result.get(cate, {}).get(name, []) if result else []
            for value in values:
                if value["origin"] in retain_origin or (
                        not ipv6_support and result and value["ipv_type"] == "ipv6"
                ):
                    whitelist_result.append(value)
                elif filter_host or not result:
                    test_result.append({**value, **get_speed_result(value["host"])} if filter_host else value)
            total_result = whitelist_result + get_sort_result(test_result, ipv6_support=ipv6_support)
            channel_result[cate][name].extend(total_result)
            for item in total_result:
                logger.info(
                    f"Name: {name}, URL: {item.get('url')}, From: {item.get('origin')}, IPv_Type: {item.get("ipv_type")}, Location: {item.get('location')}, ISP: {item.get('isp')}, Date: {item["date"]}, Delay: {item.get('delay') or -1} ms, Speed: {item.get('speed') or 0:.2f} M/s, Resolution: {item.get('resolution')}"
                )
    logger.handlers.clear()
    return channel_result

# --- (其余函数保持不变) ---
