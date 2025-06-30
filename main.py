import requests
import json
import uuid

# Cloudflare API credentials
CLOUDFLARE_API_KEY = "key"
#
#Account
#所有区域 - 区域 WAF:编辑, 区域设置:编辑, 区域:读取, 区域:编辑
#所有用户 - 用户详细信息:读取
#

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
        
        # 从ruleset中获取rules数组
        rules = ruleset.get('rules', [])
        
        # if rules:
        #     print(f"      包含 {len(rules)} 条规则:")
        #     for i, rule in enumerate(rules, 1):
        #         print(f"        规则 {i}:")
        #         print(f"          ID: {rule.get('id', 'N/A')}")
        #         print(f"          描述: {rule.get('description', 'N/A')}")
        #         #print(f"          表达式: {rule.get('expression', 'N/A')}")
        #         print(f"          动作: {rule.get('action', 'N/A')}")
        #         print(f"          启用状态: {rule.get('enabled', 'N/A')}")
        #         print(f"          最后修改: {rule.get('last_updated', 'N/A')}")
        #         print()
        # else:
        #     print("      没有找到具体规则")
            
    except requests.exceptions.RequestException as e:
        print(f"      获取ruleset详情失败: {e}")
    except ValueError as e:
        print(f"      JSON解析错误: {e}")
    
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

def add_rules_to_ruleset(zone_id, zone_name, rules_data):
    """为指定zone的现有ruleset添加规则"""
    # 先获取现有的ruleset
    ruleset = get_source_ruleset(zone_id)
    if not ruleset:
        print(f"  {zone_name} 没有找到ruleset，无法添加规则")
        return None
    
    ruleset_id = ruleset.get('id')
    ruleset_name = ruleset.get('name', 'N/A')
    
    print(f"  为 {zone_name} 的ruleset '{ruleset_name}' 添加规则...")
    
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
    return ruleset

def delete_all_rules_in_ruleset(zone_id, zone_name):
    """删除指定zone的ruleset中的所有规则"""
    # 先获取ruleset
    ruleset = get_source_ruleset(zone_id)
    if not ruleset:
        print(f"  {zone_name} 没有找到ruleset")
        return True
    
    ruleset_id = ruleset.get('id')
    ruleset_name = ruleset.get('name', 'N/A')
    
    # 获取详细的ruleset信息
    detailed_ruleset = get_ruleset_details(zone_id, ruleset_id)
    if not detailed_ruleset:
        print(f"  {zone_name} 无法获取详细ruleset信息")
        return False
    
    rules = detailed_ruleset.get('rules', [])
    if not rules:
        print(f"  {zone_name} 的ruleset中没有规则")
        return True
    
    print(f"  发现 {zone_name} 的ruleset '{ruleset_name}' 包含 {len(rules)} 条规则，正在删除...")
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # 删除所有规则
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
    
    # 获取源域名的ruleset
    source_ruleset1 = get_source_ruleset(source_zone['id'])
    if not source_ruleset1:
        print(f"在 {source_zone['name']} 中没有找到符合条件的ruleset")
        return
    
    print(f"找到源ruleset: {source_ruleset1['name']}")
    
    # 获取详细的ruleset信息（包含完整的规则数据）
    source_ruleset = get_ruleset_details(source_zone['id'], source_ruleset1['id'])
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
        
        # 删除所有现有的规则
        print(f"  检查并删除现有规则...")
        delete_success = delete_all_rules_in_ruleset(zone['id'], zone['name'])
        if not delete_success:
            print(f"  跳过 {zone['name']}，因为删除失败")
            continue
        
        # 替换规则中的主机名
        print(f"  替换规则中的主机名...")
        target_rules = replace_hostname_in_rules(rules_data, source_zone['name'], zone['name'])
        
        # 添加规则到现有ruleset
        print(f"  添加规则到现有ruleset...")
        result = add_rules_to_ruleset(zone['id'], zone['name'], target_rules)
        
        if result:
            success_count += 1
    
    print(f"\n=== 操作完成 ===")
    print(f"成功处理: {success_count}/{len(target_zones)} 个域名")

if __name__ == "__main__":
    main() 
