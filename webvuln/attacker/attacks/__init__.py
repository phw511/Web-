"""攻击函数库包：import 本包即完成全部白名单函数注册（可插拔）。"""
from webvuln.attacker.attacks import sqli_probe  # noqa: F401  （注册副作用）
from webvuln.attacker.attacks import xss_probe  # noqa: F401  （注册副作用）
