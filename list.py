import requests
import os

# Cloudflare API credentials
CLOUDFLARE_API_KEY = "key"

def get_user_info():
    """获取用户信息"""
    url = "https://api.cloudflare.com/client/v4/user"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        print(f"用户信息API响应状态码: {response.status_code}")
        print(f"响应内容: {response.text}")
        
        if response.status_code == 200:
            user_data = response.json()
            return user_data['result']['email']
        else:
            print(f"API请求失败，状态码: {response.status_code}")
            return None
    except Exception as e:
        print(f"获取用户信息失败: {e}")
        return None

def get_accounts():
    """获取账户列表"""
    url = "https://api.cloudflare.com/client/v4/accounts"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            accounts_data = response.json()
            return accounts_data['result']
        else:
            print(f"获取账户列表失败，状态码: {response.status_code}")
            return []
    except Exception as e:
        print(f"获取账户列表失败: {e}")
        return []

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
        
        if rules:
            print(f"      包含 {len(rules)} 条规则:")
            for i, rule in enumerate(rules, 1):
                print(f"        规则 {i}:")
                print(f"          ID: {rule.get('id', 'N/A')}")
                print(f"          描述: {rule.get('description', 'N/A')}")
                print(f"          表达式: {rule.get('expression', 'N/A')}")
                print(f"          动作: {rule.get('action', 'N/A')}")
                print(f"          启用状态: {rule.get('enabled', 'N/A')}")
                print(f"          最后修改: {rule.get('last_updated', 'N/A')}")
                print()
        else:
            print("      没有找到具体规则")
            
    except requests.exceptions.RequestException as e:
        print(f"      获取ruleset详情失败: {e}")
    except ValueError as e:
        print(f"      JSON解析错误: {e}")

def get_rulesets(scope, id_value):
    """获取指定账户或区域的rulesets"""
    url = f"https://api.cloudflare.com/client/v4/{scope}/{id_value}/rulesets"
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        rulesets_data = response.json()
        rulesets = rulesets_data['result']
        
        if rulesets:
            # 过滤符合条件的rulesets
            filtered_rulesets = []
            for ruleset in rulesets:
                name = ruleset.get('name', '').lower()
                kind = ruleset.get('kind', '')
                phase = ruleset.get('phase', '')
                
                # 检查是否符合条件：名称包含"default"，种类为"zone"，阶段为"http_request_firewall_custom"
                if ('default' in name and 
                    kind == 'zone' and 
                    phase == 'http_request_firewall_custom'):
                    filtered_rulesets.append(ruleset)
            
            if filtered_rulesets:
                print(f"  找到 {len(filtered_rulesets)} 个符合条件的rulesets:")
                for ruleset in filtered_rulesets:
                    print(f"    - ID: {ruleset['id']}, 名称: {ruleset['name']} ，种类: {ruleset['kind']}, 阶段: {ruleset.get('phase', 'N/A')}")
                    # 获取并显示这个ruleset的详细规则
                    get_ruleset_details(id_value, ruleset['id'])
                    print()
            else:
                print("  没有找到符合条件的rulesets")
        else:
            print("  没有找到rulesets")
            
    except requests.exceptions.RequestException as e:
        print(f"  请求错误: {e}")
    except ValueError as e:
        print(f"  JSON解析错误: {e}")

# 自动获取用户邮箱
print("正在获取用户信息...")
CLOUDFLARE_EMAIL = get_user_info()
if not CLOUDFLARE_EMAIL:
    print("无法获取用户邮箱，请检查API密钥")
    print("请确保您的API密钥是Global API Key或API Token")
    exit(1)

print(f"用户邮箱: {CLOUDFLARE_EMAIL}")

# 获取账户和区域信息
print("正在获取账户列表...")
accounts = get_accounts()

print("正在获取区域列表...")
zones = get_zones()

print(f"\n找到 {len(accounts)} 个账户:")
for account in accounts:
    print(f"  - ID: {account['id']}, 名称1: {account['name']}")

print(f"\n找到 {len(zones)} 个区域:")
for zone in zones:
    print(f"  - ID: {zone['id']}, 名称2: {zone['name']}")

# 默认使用zones
ACCOUNTS_OR_ZONES = "zones"

# 为每个账户和区域获取rulesets
if accounts:
    print(f"\n=== 获取账户的Rulesets ===")
    for account in accounts:
        print(f"\n账户: {account['name']} (ID: {account['id']})")
        get_rulesets("accounts", account['id'])

if zones:
    print(f"\n=== 获取区域的Rulesets ===")
    for zone in zones:
        print(f"\n区域: {zone['name']} (ID: {zone['id']})")
        get_rulesets("zones", zone['id'])
