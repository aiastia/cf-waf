import requests
import json
import uuid

# Cloudflare API credentials
CLOUDFLARE_API_KEY = "pkrz2em4AvYQrX4ndisahSlXaQH7swKTkao5ccdG"

PHASE_DESCRIPTIONS = {
    "http_request_origin": "源站规则（Origin Rules），控制请求到源站的行为，如修改 Host、端口等",
    "http_request_dynamic_redirect": "动态重定向规则，按条件重定向请求",
    "http_ratelimit": "速率限制规则，防止恶意流量/刷接口",
    "ddos_l7": "L7 DDoS 防护规则",
    "http_config_settings": "HTTP 配置设置规则，如自动 HTTPS、缓存等",
    "http_request_firewall_custom": "WAF 自定义防火墙规则",
    "http_request_cache_settings": "缓存设置规则",
    "http_request_sanitize": "URL 规范化/清洗规则",
    "http_response_headers_transform": "响应头修改规则"
}

def get_user_info():
    """获取用户信息"""
    url = "https://api.cloudflare.com/client/v4/user"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            return user_data['result']['email']
        else:
            print(f"获取用户信息失败，状态码: {response.status_code}")
            return None
    except Exception as e:
        print(f"获取用户信息失败: {e}")
        return None

def get_zones():
    """获取区域列表"""
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            zones_data = response.json()
            return zones_data['result']
        else:
            print(f"获取区域列表失败，状态码: {response.status_code}")
            return []
    except Exception as e:
        print(f"获取区域列表失败: {e}")
        return []

def get_source_ruleset(zone_id):
    """获取源域名的default ruleset"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        rulesets_data = response.json()
        rulesets = rulesets_data['result']
        
        # 查找符合条件的ruleset
        for ruleset in rulesets:
            name = ruleset.get('name', '').lower()
            kind = ruleset.get('kind', '')
            phase = ruleset.get('phase', '')
            
            if ('default' in name and 
                kind == 'zone' and 
                phase == 'http_request_firewall_custom'):
                return ruleset
        
        return None
            
    except requests.exceptions.RequestException as e:
        print(f"获取ruleset失败: {e}")
        return None

def get_all_rulesets(zone_id):
    """获取指定zone下的所有ruleset"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        rulesets_data = response.json()
        return rulesets_data['result']
    except Exception as e:
        print(f"获取ruleset失败: {e}")
        return []

def get_ruleset_details(zone_id, ruleset_id):
    """获取指定zone中ruleset的详细规则信息"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        ruleset_data = response.json()
        ruleset = ruleset_data['result']
    except requests.exceptions.RequestException as e:
        print(f"      获取ruleset详情失败: {e}")
        return None
    except ValueError as e:
        print(f"      JSON解析错误: {e}")
        return None
    return ruleset

def delete_ruleset(zone_id, ruleset_id, zone_name):
    """删除指定的ruleset"""
    # 先获取详细的ruleset信息
    get_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        # 获取ruleset详细信息
        get_response = requests.get(get_url, headers=headers)
        get_response.raise_for_status()
        ruleset_data = get_response.json()
        ruleset = ruleset_data['result']
        
        print(f"  获取到ruleset详情，包含 {len(ruleset.get('rules', []))} 条规则")
        
        # 删除ruleset
        delete_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
        delete_response = requests.delete(delete_url, headers=headers)
        
        if delete_response.status_code == 200:
            print(f"  ✅ 成功删除 {zone_name} 的现有ruleset")
            return True
        else:
            print(f"  ❌ 删除 {zone_name} 的ruleset失败，状态码: {delete_response.status_code}")
            print(f"  响应内容: {delete_response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"  ❌ 删除 {zone_name} 的ruleset失败: {e}")
        return False

def add_rules_to_ruleset(zone_id, zone_name, ruleset_id, rules_data):
    """为指定zone的指定ruleset添加规则"""
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    # 为ruleset添加规则
    rules_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules"
    success_count = 0
    for rule in rules_data:
        try:
            rule_response = requests.post(rules_url, headers=headers, json=rule)
            rule_response.raise_for_status()
            rule_result = rule_response.json()
            if rule_result.get('success'):
                print(f"    ✅ 添加规则: {rule.get('description', 'N/A')}")
                success_count += 1
            else:
                print(f"    ❌ 添加规则失败: {rule_result.get('errors', [])}")
        except requests.exceptions.RequestException as e:
            print(f"    ❌ 添加规则失败: {e}")
    print(f"  ✅ 成功为 {zone_name} 添加了 {success_count} 条规则")
    return True

def delete_all_rules_in_ruleset(zone_id, zone_name, ruleset_id):
    """删除指定zone的指定ruleset中的所有规则"""
    # 获取详细的ruleset信息
    detailed_ruleset = get_ruleset_details(zone_id, ruleset_id)
    if not detailed_ruleset:
        print(f"  {zone_name} 无法获取详细ruleset信息")
        return False
    rules = detailed_ruleset.get('rules', [])
    if not rules:
        print(f"  {zone_name} 的ruleset中没有规则")
        return True
    print(f"  发现 {zone_name} 的ruleset包含 {len(rules)} 条规则，正在删除...")
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    for rule in rules:
        rule_id = rule.get('id')
        rule_description = rule.get('description', 'N/A')
        if rule_id:
            delete_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
            try:
                delete_response = requests.delete(delete_url, headers=headers)
                if delete_response.status_code == 200:
                    print(f"    ✅ 删除规则: {rule_description} (ID: {rule_id})")
                else:
                    print(f"    ❌ 删除规则失败: {rule_description}，状态码: {delete_response.status_code}")
            except Exception as e:
                print(f"    ❌ 删除规则失败: {rule_description}，错误: {e}")
    print(f"  ✅ 完成删除 {zone_name} 的所有规则")
    return True

def replace_hostname_in_rules(rules_data, source_domain, target_domain):
    """替换规则中的主机名从源域名到目标域名"""
    modified_rules = []
    
    for rule in rules_data:
        rule_copy = rule.copy()
        expression = rule_copy.get('expression', '')
        
        # 替换主机名
        if source_domain in expression:
            new_expression = expression.replace(source_domain, target_domain)
            rule_copy['expression'] = new_expression
            print(f"    替换主机名: {source_domain} -> {target_domain}")
            print(f"    原表达式: {expression}")
            print(f"    新表达式: {new_expression}")
        
        modified_rules.append(rule_copy)
    
    return modified_rules

def update_origin_ruleset(zone_id, ruleset_id, rules):
    """整体替换 Origin Rules（phase: http_request_origin）"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {"rules": rules}
    try:
        response = requests.put(url, headers=headers, json=data)
        if response.status_code == 200:
            print("  ✅ Origin ruleset 替换成功")
            return True
        else:
            print(f"  ❌ 替换失败: {response.status_code} {response.text}")
            return False
    except Exception as e:
        print(f"  ❌ 替换失败: {e}")
        return False

def get_zone_ruleset_by_phase(zone_id, phase):
    """查找指定 zone 下 phase=xxx 的 zone ruleset"""
    rulesets = get_all_rulesets(zone_id)
    for rs in rulesets:
        if rs.get('kind') == 'zone' and rs.get('phase') == phase:
            return rs
    return None

def create_zone_ruleset(zone_id, phase, name='Custom Origin Ruleset'):
    """为 zone 创建指定 phase 的 ruleset（kind: zone）"""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "name": name,
        "kind": "zone",
        "phase": phase,
        "description": f"Auto-created ruleset for {phase}",
        "rules": []
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"  ✅ 已自动创建 phase={phase} 的 zone ruleset")
            return response.json()['result']
        else:
            print(f"  ❌ 创建 ruleset 失败: {response.status_code} {response.text}")
            return None
    except Exception as e:
        print(f"  ❌ 创建 ruleset 失败: {e}")
        return None

def main():
    print("=== Cloudflare WAF规则复制工具 ===")
    
    # 获取用户邮箱
    email = get_user_info()
    if not email:
        print("无法获取用户信息，请检查API密钥")
        return
    
    print(f"用户邮箱: {email}")
    
    # 获取所有区域
    zones = get_zones()
    if not zones:
        print("没有找到任何区域")
        return
    
    print(f"\n找到 {len(zones)} 个区域:")
    for i, zone in enumerate(zones, 1):
        print(f"  {i}. {zone['name']} (ID: {zone['id']})")
    
    # 选择源域名
    print(f"\n请选择源域名（输入数字1-{len(zones)}）:")
    try:
        source_index = int(input()) - 1
        if source_index < 0 or source_index >= len(zones):
            print("无效的选择")
            return
        source_zone = zones[source_index]
    except ValueError:
        print("请输入有效的数字")
        return
    
    print(f"\n选择的源域名: {source_zone['name']}")
    
    # 新增：只显示 kind == 'zone' 的 ruleset
    all_rulesets = get_all_rulesets(source_zone['id'])
    zone_rulesets = [rs for rs in all_rulesets if rs.get('kind') == 'zone']
    if not zone_rulesets:
        print(f"在 {source_zone['name']} 中没有可迁移的自定义 ruleset")
        return
    print(f"\n可迁移的 ruleset:")
    for i, rs in enumerate(zone_rulesets, 1):
        phase = rs.get('phase', '')
        desc = PHASE_DESCRIPTIONS.get(phase, '')
        print(f"  {i}. name: {rs.get('name','')} | phase: {phase} | id: {rs.get('id','')} | {desc}")
    print(f"\n请选择要迁移的 ruleset（输入数字1-{len(zone_rulesets)}）:")
    try:
        ruleset_index = int(input()) - 1
        if ruleset_index < 0 or ruleset_index >= len(zone_rulesets):
            print("无效的选择")
            return
        selected_ruleset = zone_rulesets[ruleset_index]
    except ValueError:
        print("请输入有效的数字")
        return
    print(f"\n选择的ruleset: {selected_ruleset.get('name','')} | phase: {selected_ruleset.get('phase','')}")
    
    # 获取详细的ruleset信息
    source_ruleset = get_ruleset_details(source_zone['id'], selected_ruleset['id'])
    if not source_ruleset:
        print(f"无法获取 {source_zone['name']} 的详细ruleset信息")
        return
    print(f"包含 {len(source_ruleset.get('rules', []))} 条规则")
    
    # 显示源规则
    print("\n源规则列表:")
    for i, rule in enumerate(source_ruleset.get('rules', []), 1):
        print(f"  {i}. {rule.get('description', 'N/A')} - {rule.get('action', 'N/A')} (ID: {rule.get('id', 'N/A')})")
    
    # 选择要复制的规则
    print(f"\n请选择要复制的规则（输入数字，用逗号分隔多个，或输入'all'选择所有）:")
    rule_input = input().strip()
    
    selected_rules = []
    if rule_input.lower() == 'all':
        selected_rules = source_ruleset.get('rules', [])
        print(f"选择复制所有 {len(selected_rules)} 条规则")
    else:
        try:
            rule_indices = [int(x.strip()) - 1 for x in rule_input.split(',')]
            all_rules = source_ruleset.get('rules', [])
            selected_rules = [all_rules[i] for i in rule_indices if 0 <= i < len(all_rules)]
            print(f"选择复制 {len(selected_rules)} 条规则")
        except ValueError:
            print("输入格式错误，将复制所有规则")
            selected_rules = source_ruleset.get('rules', [])
    
    if not selected_rules:
        print("没有选择任何规则，操作取消")
        return
    
    # 选择目标域名
    print(f"\n请选择目标域名（输入数字，用逗号分隔多个，或输入'all'选择所有）:")
    target_input = input().strip()
    
    target_zones = []
    if target_input.lower() == 'all':
        target_zones = [z for z in zones if z['id'] != source_zone['id']]
    else:
        try:
            target_indices = [int(x.strip()) - 1 for x in target_input.split(',')]
            target_zones = [zones[i] for i in target_indices if 0 <= i < len(zones) and zones[i]['id'] != source_zone['id']]
        except ValueError:
            print("输入格式错误")
            return
    
    if not target_zones:
        print("没有选择有效的目标域名")
        return
    
    print(f"\n选择的目标域名:")
    for zone in target_zones:
        print(f"  - {zone['name']}")
    
    # 显示选择的规则
    print(f"\n选择的规则:")
    for i, rule in enumerate(selected_rules, 1):
        print(f"  {i}. {rule.get('description', 'N/A')} - {rule.get('action', 'N/A')}")
    
    # 确认操作
    print(f"\n确认要将 {source_zone['name']} 的 {len(selected_rules)} 条规则复制到 {len(target_zones)} 个域名吗？(y/n):")
    confirm = input().strip().lower()
    if confirm != 'y':
        print("操作已取消")
        return
    
    # 准备规则数据（移除不需要的字段）
    rules_data = []
    print(f"\n准备规则数据...")
    for i, rule in enumerate(selected_rules, 1):
        print(f"  处理源规则 {i}: {rule.get('description', 'N/A')}")
        
        rule_copy = {
            'description': rule.get('description', ''),
            'expression': rule.get('expression', ''),
            'action': rule.get('action', ''),
            'enabled': rule.get('enabled', True)
        }
        
        # 添加action_parameters如果存在
        if 'action_parameters' in rule:
            rule_copy['action_parameters'] = rule['action_parameters']
            print(f"    包含action_parameters: {rule['action_parameters']}")
        
        # 添加logging如果存在
        if 'logging' in rule:
            rule_copy['logging'] = rule['logging']
            print(f"    包含logging: {rule['logging']}")
        
        print(f"    规则数据: {json.dumps(rule_copy, indent=2)}")
        rules_data.append(rule_copy)
    
    print(f"总共准备了 {len(rules_data)} 条规则")
    
    # 复制规则到目标域名
    print(f"\n开始复制规则...")
    success_count = 0
    
    for zone in target_zones:
        print(f"\n处理域名: {zone['name']}")
        # 查找目标域名下同类型ruleset
        target_ruleset = get_zone_ruleset_by_phase(zone['id'], selected_ruleset.get('phase'))
        if not target_ruleset:
            print(f"  没有找到 phase={selected_ruleset.get('phase')} kind=zone 的ruleset，自动创建...")
            target_ruleset = create_zone_ruleset(zone['id'], selected_ruleset.get('phase'))
            if not target_ruleset:
                print(f"  创建失败，跳过")
                continue
        # 替换规则中的主机名
        print(f"  替换规则中的主机名...")
        target_rules = replace_hostname_in_rules(rules_data, source_zone['name'], zone['name'])
        # 根据 phase 选择 API 操作
        if selected_ruleset.get('phase') == 'http_request_origin':
            # Origin Rules: 直接整体替换
            print(f"  用 PUT 替换 Origin Ruleset ...")
            result = update_origin_ruleset(zone['id'], target_ruleset['id'], target_rules)
        else:
            # 其它类型，先删后加
            print(f"  检查并删除现有规则...")
            delete_success = delete_all_rules_in_ruleset(zone['id'], zone['name'], target_ruleset['id'])
            if not delete_success:
                print(f"  跳过 {zone['name']}，因为删除失败")
                continue
            print(f"  添加规则到现有ruleset...")
            result = add_rules_to_ruleset(zone['id'], zone['name'], target_ruleset['id'], target_rules)
        if result:
            success_count += 1
    
    print(f"\n=== 操作完成 ===")
    print(f"成功处理: {success_count}/{len(target_zones)} 个域名")

if __name__ == "__main__":
    main() 
    main() 
