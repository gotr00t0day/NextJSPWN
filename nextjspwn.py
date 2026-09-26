#!/usr/bin/env python3
"""
NextJSPwn - Unified Next.js Vulnerability Testing Framework
Author: c0d3ninja
Website: gotr00t0day.github.io
Version: 1.0.0

A comprehensive framework for testing Next.js applications against known CVEs.

Supported CVEs:
  • CVE-2025-29927 - Middleware Authorization Bypass (CRITICAL - CVSS 9.1)
  • CVE-2024-51479 - Authorization Bypass, pathname middleware (HIGH - CVSS 7.5)
  • CVE-2024-34351 - Server Actions SSRF, Host header (HIGH - CVSS 7.5)
  • CVE-2024-46982 - Cache Poisoning, SSR forced to SSG (HIGH - CVSS 7.5)
  • CVE-2025-57822 - Middleware SSRF (MEDIUM - CVSS 6.5)
  • CVE-2025-57752 - Image Optimizer Cache Deception (MEDIUM - CVSS 6.5)
  • CVE-2025-55173 - Image Optimization Content Injection (MEDIUM - CVSS 6.5)
  • CVE-2025-49826 - Cache Poisoning to DoS, HTTP 204 (MEDIUM - CVSS 5.9)
  • CVE-2025-32421 - Race Condition Information Disclosure (MEDIUM - CVSS 5.3)
  • CVE-2025-48068 - Dev Server Info Exposure, CSWSH/XSSI (LOW - CVSS 4.3)
"""

import sys
import os
import argparse
import importlib.util
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "1.0.0"

class NextJSPwn:

    CVE_REGISTRY = {
        'CVE-2024-51479': {'class': 'NextJSAuthzBypass', 'severity': 'HIGH', 'cvss': 7.5,
                           'name': 'Authorization Bypass (pathname middleware)'},
        'CVE-2024-34351': {'class': 'NextJSServerActionSSRF', 'severity': 'HIGH', 'cvss': 7.5,
                           'name': 'Server Actions SSRF (Host header)', 'callback': True},
        'CVE-2024-46982': {'class': 'NextJSCachePoisoning', 'severity': 'HIGH', 'cvss': 7.5,
                           'name': 'Cache Poisoning (SSR forced to SSG)'},
        'CVE-2025-57752': {'class': 'NextJSImageCacheDeception', 'severity': 'MEDIUM', 'cvss': 6.5,
                           'name': 'Image Optimizer Cache Deception (authz bypass)'},
        'CVE-2025-55173': {'class': 'NextJSImageContentInjection', 'severity': 'MEDIUM', 'cvss': 6.5,
                           'name': 'Image Optimization Content Injection'},
        'CVE-2025-49826': {'class': 'NextJSCacheDoS', 'severity': 'MEDIUM', 'cvss': 5.9,
                           'name': 'Cache Poisoning -> DoS (HTTP 204)'},
        'CVE-2025-48068': {'class': 'NextJSDevServerLeak', 'severity': 'LOW', 'cvss': 4.3,
                           'name': 'Dev Server Info Exposure (CSWSH/XSSI)'},
    }

    ALL_CVES = [
        'CVE-2025-29927',
        'CVE-2024-51479',
        'CVE-2024-34351',
        'CVE-2024-46982',
        'CVE-2025-57822',
        'CVE-2025-57752',
        'CVE-2025-55173',
        'CVE-2025-49826',
        'CVE-2025-32421',
        'CVE-2025-48068',
    ]

    def __init__(self, target: str, timeout: int = 15, debug: bool = False,
                 verify_ssl: bool = True, proxy: Optional[str] = None,
                 callback: Optional[str] = None, verbose: bool = True,
                 concurrency: int = 1):
        self.target = target
        self.timeout = timeout
        self.debug = debug
        self.verbose = verbose
        self.concurrency = max(1, concurrency)
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.callback = callback

        self._results_lock = threading.Lock()
        self._tls = threading.local()

        self.base_dir = Path(__file__).parent

        self._recon_done = False
        self._shared_is_nextjs: Optional[bool] = None
        self._shared_version: Optional[str] = None
        
        self.results = {
            'target': target,
            'cves_tested': [],
            'vulnerabilities': [],
            'version': None,
            'is_nextjs': False
        }
    
    def _log(self, msg: str, level: str = "INFO"):
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "ERROR": Fore.RED,
            "WARNING": Fore.YELLOW,
            "DEBUG": Fore.MAGENTA,
            "VULN": Fore.RED + Style.BRIGHT,
            "TITLE": Fore.YELLOW + Style.BRIGHT
        }
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "ERROR": "[!]",
            "WARNING": "[~]",
            "DEBUG": "[D]",
            "VULN": "[!]",
            "TITLE": "[#]"
        }

        if level == "DEBUG" and not self.debug:
            return
        if not (self.debug or self.verbose or level in ("VULN", "ERROR")):
            return

        self._emit(f"{colors.get(level, Fore.WHITE)}{prefix.get(level, '[*]')} {msg}{Style.RESET_ALL}")

    def _emit(self, text: str):
        buf = getattr(self._tls, 'buffer', None)
        if buf is not None:
            buf.append(text)
        else:
            print(text)

    def _merge_result(self, result: Dict, vuln_record: Optional[Dict] = None):
        with self._results_lock:
            cve = result.get('cve')
            if cve and cve not in self.results['cves_tested']:
                self.results['cves_tested'].append(cve)
            if result.get('exploitable'):
                self.results['vulnerabilities'].append(vuln_record or result)
            if result.get('version') and not self.results['version']:
                self.results['version'] = result['version']
            if result.get('is_nextjs') and not self.results['is_nextjs']:
                self.results['is_nextjs'] = True
    
    def load_module(self, cve_id: str):
        module_map = {
            'CVE-2025-29927': 'CVE-2025-29927/nextjs_middleware_bypass.py',
            'CVE-2025-57822': 'CVE-2025-57822/nextjs_ssrf_exploit.py',
            'CVE-2025-32421': 'CVE-2025-32421/nextjs_race_condition.py',
            'CVE-2024-51479': 'CVE-2024-51479/nextjs_authz_bypass.py',
            'CVE-2024-34351': 'CVE-2024-34351/nextjs_serveraction_ssrf.py',
            'CVE-2024-46982': 'CVE-2024-46982/nextjs_cache_poisoning.py',
            'CVE-2025-57752': 'CVE-2025-57752/nextjs_image_cache_deception.py',
            'CVE-2025-55173': 'CVE-2025-55173/nextjs_image_content_injection.py',
            'CVE-2025-49826': 'CVE-2025-49826/nextjs_cache_dos.py',
            'CVE-2025-48068': 'CVE-2025-48068/nextjs_devserver_leak.py',
        }
        
        if cve_id not in module_map:
            self._log(f"Unknown CVE: {cve_id}", "ERROR")
            return None
        
        module_path = self.base_dir / module_map[cve_id]
        
        if not module_path.exists():
            self._log(f"Module not found: {module_path}", "ERROR")
            return None
        
        try:
            spec = importlib.util.spec_from_file_location(f"cve_{cve_id.replace('-', '_')}", module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            self._log(f"Failed to load module {cve_id}: {e}", "ERROR")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return None
    
    def _shared_recon(self):
        if self._recon_done:
            return
        self._recon_done = True
        try:
            if str(self.base_dir) not in sys.path:
                sys.path.insert(0, str(self.base_dir))
            from _nextjs_common import NextJSCommon
            probe = NextJSCommon(self.target, self.timeout, self.debug,
                                 self.verify_ssl, self.proxy, verbose=self.verbose)
            probe._sink = getattr(self._tls, 'buffer', None)
            self._shared_is_nextjs = probe.detect_nextjs()
            self._shared_version = probe.extract_version() if self._shared_is_nextjs else None
            self.results['version_source'] = probe.version_source
            self.results['router'] = probe.router
            self.results['inferred_version'] = probe.inferred
        except Exception as e:
            self._log(f"Shared recon failed ({e}); modules will self-detect.", "WARNING")
            self._shared_is_nextjs = None
            self._shared_version = None

        self.results['is_nextjs'] = bool(self._shared_is_nextjs)
        if self._shared_version and not self.results['version']:
            self.results['version'] = self._shared_version

    def test_registered_cve(self, cve_id: str) -> Dict:
        meta = self.CVE_REGISTRY.get(cve_id)
        if not meta:
            self._log(f"CVE not in registry: {cve_id}", "ERROR")
            return {'error': 'Not registered'}

        self._log(f"Testing {cve_id}: {meta['name']} ({meta['severity']})", "TITLE")

        self._shared_recon()
        if self._shared_is_nextjs is False:
            self._log("Target is not Next.js; skipping.", "WARNING")
            with self._results_lock:
                if cve_id not in self.results['cves_tested']:
                    self.results['cves_tested'].append(cve_id)
            return {'cve': cve_id, 'name': meta['name'], 'severity': meta['severity'],
                    'cvss': meta['cvss'], 'is_nextjs': False, 'version': None,
                    'vulnerable_version': None, 'exploitable': False}

        module = self.load_module(cve_id)
        if not module:
            return {'error': 'Module failed to load'}

        try:
            cls = getattr(module, meta['class'])
            exploit = cls(
                target=self.target,
                timeout=self.timeout,
                debug=self.debug,
                verify_ssl=self.verify_ssl,
                proxy=self.proxy,
                verbose=self.verbose
            )
            exploit._sink = getattr(self._tls, 'buffer', None)

            if self._shared_is_nextjs:
                exploit.is_nextjs = True
                exploit.version = self._shared_version
                exploit._recon_seeded = True

            scan_kwargs = {}
            if meta.get('callback') and self.callback:
                scan_kwargs['callback_url'] = self.callback

            exploit.full_scan(**scan_kwargs)

            result = {
                'cve': cve_id,
                'name': meta['name'],
                'severity': meta['severity'],
                'cvss': meta['cvss'],
                'is_nextjs': exploit.is_nextjs,
                'version': exploit.version,
                'vulnerable_version': exploit.check_version_vulnerable() if exploit.version else None,
                'exploitable': exploit.vulnerable,
            }

            self._merge_result(result)
            return result

        except Exception as e:
            self._log(f"Error testing {cve_id}: {e}", "ERROR")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return {'error': str(e)}

    def run_cve(self, cve_id: str, iterations: int = 10) -> Dict:
        if cve_id == 'CVE-2025-29927':
            return self.test_cve_2025_29927()
        elif cve_id == 'CVE-2025-57822':
            return self.test_cve_2025_57822()
        elif cve_id == 'CVE-2025-32421':
            return self.test_cve_2025_32421(iterations=iterations)
        else:
            return self.test_registered_cve(cve_id)

    def test_cve_2025_29927(self) -> Dict:
        self._log("Testing CVE-2025-29927: Middleware Authorization Bypass (CRITICAL)", "TITLE")
        
        module = self.load_module('CVE-2025-29927')
        if not module:
            return {'error': 'Module failed to load'}
        
        try:
            exploit = module.NextJSMiddlewareBypass(
                target=self.target,
                timeout=self.timeout,
                debug=self.debug,
                verify_ssl=self.verify_ssl,
                proxy=self.proxy
            )
            exploit.verbose = self.verbose
            exploit._sink = getattr(self._tls, 'buffer', None)
            if self._shared_is_nextjs:
                exploit.is_nextjs = True
                if self._shared_version:
                    exploit.version = self._shared_version

            results = exploit.full_scan()
            
            result = {
                'cve': 'CVE-2025-29927',
                'name': 'Middleware Authorization Bypass',
                'severity': 'CRITICAL',
                'cvss': 9.1,
                'is_nextjs': exploit.is_nextjs,
                'version': exploit.version,
                'vulnerable_version': exploit.check_version_vulnerable() if exploit.version else None,
                'exploitable': exploit.vulnerable,
                'bypassed_endpoints': exploit.bypassed_endpoints,
                'results': results
            }

            self._merge_result(result)
            return result
        
        except Exception as e:
            self._log(f"Error testing CVE-2025-29927: {e}", "ERROR")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return {'error': str(e)}
    
    def test_cve_2025_57822(self) -> Dict:
        self._log("Testing CVE-2025-57822: Middleware SSRF (MEDIUM)", "TITLE")
        
        module = self.load_module('CVE-2025-57822')
        if not module:
            return {'error': 'Module failed to load'}
        
        try:
            exploit = module.NextJSSSRFExploit(
                target=self.target,
                timeout=self.timeout,
                debug=self.debug,
                verify_ssl=self.verify_ssl,
                proxy=self.proxy
            )
            exploit.verbose = self.verbose
            exploit._sink = getattr(self._tls, 'buffer', None)

            if self._shared_is_nextjs:
                exploit.is_nextjs = True
                exploit.version = self._shared_version
            else:
                exploit.detect_nextjs()
            if not exploit.version:
                exploit.extract_version()
            version_vuln = exploit.check_version_vulnerable()
            
            if version_vuln is not False:
                exploit.test_ssrf_internal()
            
            result = {
                'cve': 'CVE-2025-57822',
                'name': 'Middleware SSRF',
                'severity': 'MEDIUM',
                'cvss': 6.5,
                'is_nextjs': exploit.is_nextjs,
                'version': exploit.version,
                'vulnerable_version': version_vuln,
                'exploitable': exploit.vulnerable,
                'note': 'Full SSRF testing requires callback URL (use --callback)'
            }

            self._merge_result(result)
            return result
        
        except Exception as e:
            self._log(f"Error testing CVE-2025-57822: {e}", "ERROR")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return {'error': str(e)}
    
    def test_cve_2025_32421(self, iterations: int = 10) -> Dict:
        self._log("Testing CVE-2025-32421: Race Condition Information Disclosure (MEDIUM)", "TITLE")
        
        module = self.load_module('CVE-2025-32421')
        if not module:
            return {'error': 'Module failed to load'}
        
        try:
            exploit = module.NextJSRaceCondition(
                target=self.target,
                timeout=self.timeout,
                debug=self.debug,
                verify_ssl=self.verify_ssl,
                proxy=self.proxy
            )
            exploit.verbose = self.verbose
            exploit._sink = getattr(self._tls, 'buffer', None)
            if self._shared_is_nextjs:
                exploit.is_nextjs = True
                if self._shared_version:
                    exploit.version = self._shared_version

            results = exploit.full_scan(iterations=iterations)
            
            result = {
                'cve': 'CVE-2025-32421',
                'name': 'Race Condition Information Disclosure',
                'severity': 'MEDIUM',
                'cvss': 5.3,
                'is_nextjs': exploit.is_nextjs,
                'version': exploit.version,
                'vulnerable_version': exploit.check_version_vulnerable() if exploit.version else None,
                'exploitable': exploit.vulnerable,
                'leaked_data': exploit.leaked_data,
                'results': results
            }

            self._merge_result(result)
            return result
        
        except Exception as e:
            self._log(f"Error testing CVE-2025-32421: {e}", "ERROR")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return {'error': str(e)}
    
    def scan_all(self, iterations: int = 10) -> Dict:
        self._log(f"\nStarting comprehensive NextJSPwn scan on {self.target}", "INFO")

        self._shared_recon()
        if self._shared_is_nextjs is False:
            self._log(f"{self.target} does not appear to be a Next.js application; "
                      "skipping all CVE checks.", "WARNING")
            self.results['individual_results'] = []
            return self.results

        mode = f"{self.concurrency} workers" if self.concurrency > 1 else "sequential"
        self._log(f"Testing {len(self.ALL_CVES)} CVEs ({mode})...\n", "INFO")

        if self.concurrency > 1:
            results = self._scan_concurrent(self.ALL_CVES, iterations=iterations)
        else:
            results = []
            for cve_id in self.ALL_CVES:
                results.append(self.run_cve(cve_id, iterations=iterations))
                self._emit("")

        self.results['individual_results'] = results
        return self.results

    def _run_cve_buffered(self, cve_id: str, iterations: int):
        buf: List[str] = []
        self._tls.buffer = buf
        try:
            result = self.run_cve(cve_id, iterations=iterations)
        except Exception as e:
            result = {'cve': cve_id, 'error': str(e)}
        finally:
            self._tls.buffer = None
        return cve_id, result, buf

    def _scan_concurrent(self, cve_ids: List[str], iterations: int = 10) -> List[Dict]:
        results_by_cve: Dict[str, Dict] = {}
        buffers_by_cve: Dict[str, List[str]] = {}

        workers = min(self.concurrency, len(cve_ids))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._run_cve_buffered, cve, iterations): cve
                       for cve in cve_ids}
            for fut in as_completed(futures):
                cve_id, result, buf = fut.result()
                results_by_cve[cve_id] = result
                buffers_by_cve[cve_id] = buf

        ordered: List[Dict] = []
        for cve_id in cve_ids:
            for line in buffers_by_cve.get(cve_id, []):
                print(line)
            if buffers_by_cve.get(cve_id):
                print()
            if cve_id in results_by_cve:
                ordered.append(results_by_cve[cve_id])
        return ordered
    
    def print_summary(self):
        self._emit(f"\n{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}\n")

        self._emit(f"  {Fore.WHITE}Target:{Style.RESET_ALL}              {self.results['target']}")
        self._emit(f"  {Fore.WHITE}Next.js Detected:{Style.RESET_ALL}    {'Yes' if self.results['is_nextjs'] else 'No'}")
        if self.results['version']:
            src = self.results.get('version_source')
            src_note = f" {Fore.WHITE}(via {src}){Style.RESET_ALL}" if src else ""
            self._emit(f"  {Fore.WHITE}Version:{Style.RESET_ALL}              {self.results['version']}{src_note}")
        elif self.results.get('inferred_version'):
            self._emit(f"  {Fore.WHITE}Version:{Style.RESET_ALL}              "
                       f"{Fore.YELLOW}unknown{Style.RESET_ALL} ({self.results['inferred_version']})")
        self._emit(f"  {Fore.WHITE}CVEs Tested:{Style.RESET_ALL}         {len(self.results['cves_tested'])}")

        vuln_count = len(self.results['vulnerabilities'])
        if vuln_count > 0:
            self._emit(f"  {Fore.RED}Vulnerabilities:{Style.RESET_ALL}      {vuln_count} {Fore.RED}FOUND{Style.RESET_ALL}")
        else:
            self._emit(f"  {Fore.GREEN}Vulnerabilities:{Style.RESET_ALL}      {vuln_count} (Secure){Style.RESET_ALL}")

        if self.results.get('individual_results'):
            self._emit(f"\n{Fore.CYAN}RESULTS{Style.RESET_ALL}\n")

            for result in self.results['individual_results']:
                if 'error' in result:
                    continue

                cve = result.get('cve', 'Unknown')
                name = result.get('name', 'Unknown')
                severity = result.get('severity', 'Unknown')
                cvss = result.get('cvss', 'N/A')
                exploitable = result.get('exploitable', False)

                if severity == 'CRITICAL':
                    color = Fore.RED + Style.BRIGHT
                elif severity == 'HIGH':
                    color = Fore.RED
                elif severity == 'MEDIUM':
                    color = Fore.YELLOW
                else:
                    color = Fore.GREEN

                status = f"{Fore.RED}EXPLOITABLE{Style.RESET_ALL}" if exploitable else f"{Fore.GREEN}NOT EXPLOITABLE{Style.RESET_ALL}"

                self._emit(f"  {color}{cve}{Style.RESET_ALL} {name}")
                self._emit(f"    Severity: {color}{severity}{Style.RESET_ALL} (CVSS {cvss})")
                self._emit(f"    Status: {status}")

                if result.get('vulnerable_version') is True:
                    self._emit(f"    Version: {Fore.YELLOW}Vulnerable{Style.RESET_ALL}")
                elif result.get('vulnerable_version') is False:
                    self._emit(f"    Version: {Fore.GREEN}Patched{Style.RESET_ALL}")
                self._emit("")

        if vuln_count > 0:
            self._emit(f"{Fore.RED}ACTION REQUIRED{Style.RESET_ALL}")
            self._emit(f"  • Review exploitable endpoints")
            self._emit(f"  • Update Next.js to latest version")
            self._emit(f"  • Implement additional security controls")
        else:
            self._emit(f"{Fore.GREEN}✓ No exploitable vulnerabilities found{Style.RESET_ALL}")
            if self.results['version']:
                self._emit(f"  Consider keeping Next.js updated")


def print_banner():
    banner = f"""
{Fore.RED}

                                                                       
███╗   ██╗███████╗██╗  ██╗████████╗  ██╗███████╗██████╗ ██╗    ██╗███╗   ██╗
████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝  ██║██╔════╝██╔══██╗██║    ██║████╗  ██║
██╔██╗ ██║█████╗   ╚███╔╝    ██║     ██║███████╗██████╔╝██║ █╗ ██║██╔██╗ ██║
██║╚██╗██║██╔══╝   ██╔██╗    ██║██   ██║╚════██║██╔═══╝ ██║███╗██║██║╚██╗██║
██║ ╚████║███████╗██╔╝ ██╗   ██║╚█████╔╝███████║██║     ╚███╔███╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝ ╚════╝ ╚══════╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝                     
                                                                       

{Fore.CYAN}    Next.js Unified Exploitation Framework v{VERSION}
{Fore.CYAN}    Author: c0d3ninja
{Fore.CYAN}    Supported CVEs: 10 (CVE-2024-34351, CVE-2024-46982, CVE-2024-51479,
{Fore.CYAN}                       CVE-2025-29927, CVE-2025-32421, CVE-2025-48068,
{Fore.CYAN}                       CVE-2025-49826, CVE-2025-55173, CVE-2025-57752,
{Fore.CYAN}                       CVE-2025-57822)
{Style.RESET_ALL}
"""
    print(banner)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='NextJSPwn - Unified Next.js Vulnerability Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.YELLOW}Supported CVEs:{Style.RESET_ALL}
  • CVE-2025-29927  Middleware Authorization Bypass (CRITICAL - CVSS 9.1)
  • CVE-2024-51479  Authorization Bypass, pathname middleware (HIGH - CVSS 7.5)
  • CVE-2024-34351  Server Actions SSRF, Host header (HIGH - CVSS 7.5)
  • CVE-2024-46982  Cache Poisoning, SSR forced to SSG (HIGH - CVSS 7.5)
  • CVE-2025-57822  Middleware SSRF (MEDIUM - CVSS 6.5)
  • CVE-2025-57752  Image Optimizer Cache Deception (MEDIUM - CVSS 6.5)
  • CVE-2025-55173  Image Optimization Content Injection (MEDIUM - CVSS 6.5)
  • CVE-2025-49826  Cache Poisoning to DoS, HTTP 204 (MEDIUM - CVSS 5.9)
  • CVE-2025-32421  Race Condition Info Disclosure (MEDIUM - CVSS 5.3)
  • CVE-2025-48068  Dev Server Info Exposure, CSWSH/XSSI (LOW - CVSS 4.3)

{Fore.CYAN}Examples:{Style.RESET_ALL}
  # Test all CVEs (comprehensive scan)
  {Fore.WHITE}%(prog)s -t https://example.com{Style.RESET_ALL}
  
  # Test specific CVE
  {Fore.WHITE}%(prog)s -t https://example.com -cve CVE-2025-29927{Style.RESET_ALL}
  
  # Test multiple CVEs
  {Fore.WHITE}%(prog)s -t https://example.com -cve CVE-2025-29927 CVE-2025-57822{Style.RESET_ALL}
  
  # With Burp proxy and debug
  {Fore.WHITE}%(prog)s -t https://example.com --proxy http://127.0.0.1:8080 -k --debug{Style.RESET_ALL}
  
  # Scan from file (10 targets in parallel)
  {Fore.WHITE}%(prog)s -f targets.txt -c 10{Style.RESET_ALL}

  # Verbose output (see everything, not just findings)
  {Fore.WHITE}%(prog)s -t https://example.com -v{Style.RESET_ALL}

  # Fast parallel CVE scan of one target
  {Fore.WHITE}%(prog)s -t https://example.com -c 10{Style.RESET_ALL}

  # Sequential / stealthier (one request path at a time)
  {Fore.WHITE}%(prog)s -t https://example.com -c 1{Style.RESET_ALL}

  # Custom race condition iterations
  {Fore.WHITE}%(prog)s -t https://example.com -cve CVE-2025-32421 --iterations 20{Style.RESET_ALL}
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Target URL')
    target_group.add_argument('-f', '--file', help='File containing target URLs')
    
    parser.add_argument('-cve', '--cve', nargs='+',
                       choices=NextJSPwn.ALL_CVES + ['all'],
                       default=['all'],
                       help='CVE(s) to test (default: all)')
    
    parser.add_argument('--iterations', type=int, default=10,
                       help='Race condition attempts for CVE-2025-32421 (default: 10)')
    parser.add_argument('--callback', help='Callback URL for SSRF testing (CVE-2025-57822)')
    
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('-k', '--no-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (default: findings only)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (implies verbose)')
    parser.add_argument('-c', '--concurrency', type=int, default=5, metavar='N',
                       help='Concurrent workers: CVEs per target, or targets in file mode '
                            '(default: 5, use 1 for sequential)')
    parser.add_argument('-o', '--output', help='Save results to JSON file')

    args = parser.parse_args()

    verbose = args.verbose or args.debug
    
    cves_to_test = args.cve
    run_all = 'all' in cves_to_test
    if run_all:
        cves_to_test = list(NextJSPwn.ALL_CVES)

    if args.target:
        framework = NextJSPwn(
            target=args.target,
            timeout=args.timeout,
            debug=args.debug,
            verify_ssl=not args.no_verify,
            proxy=args.proxy,
            callback=args.callback,
            verbose=verbose,
            concurrency=args.concurrency
        )

        if run_all:
            results = framework.scan_all(iterations=args.iterations)
        else:
            framework._shared_recon()
            if framework._shared_is_nextjs is False:
                framework._log(f"{framework.target} does not appear to be a Next.js "
                               "application; skipping.", "WARNING")
            elif len(cves_to_test) > 1 and framework.concurrency > 1:
                framework.results['individual_results'] = \
                    framework._scan_concurrent(cves_to_test, iterations=args.iterations)
            else:
                for cve in cves_to_test:
                    framework.run_cve(cve, iterations=args.iterations)
                    print()
        
        framework.print_summary()
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(framework.results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] Results saved to: {args.output}{Style.RESET_ALL}")
    
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.file}{Style.RESET_ALL}")
            sys.exit(1)
        
        mode = f"{args.concurrency} concurrent targets" if args.concurrency > 1 else "sequential"
        print(f"{Fore.CYAN}[*] Loaded {len(targets)} targets from {args.file} ({mode}){Style.RESET_ALL}\n")

        def scan_one(idx_target):
            idx, target = idx_target
            framework = NextJSPwn(
                target=target,
                timeout=args.timeout,
                debug=args.debug,
                verify_ssl=not args.no_verify,
                proxy=args.proxy,
                callback=args.callback,
                verbose=verbose,
                concurrency=1
            )
            buf = []
            framework._tls.buffer = buf
            try:
                framework._emit(f"\n{Fore.CYAN}Scanning Target {idx}/{len(targets)}: "
                                f"{target}{Style.RESET_ALL}\n")
                if run_all:
                    framework.scan_all(iterations=args.iterations)
                else:
                    framework._shared_recon()
                    if framework._shared_is_nextjs is False:
                        framework._log(f"{target} is not a Next.js application; skipping.", "WARNING")
                    else:
                        for cve in cves_to_test:
                            framework.run_cve(cve, iterations=args.iterations)
                            framework._emit("")
                framework.print_summary()
            finally:
                framework._tls.buffer = None
            return framework.results, buf

        all_results = []
        indexed = list(enumerate(targets, 1))
        total = len(indexed)
        if args.concurrency > 1:
            done = 0
            print(f"{Fore.CYAN}[*] Scanning {total} targets with {min(args.concurrency, total)} "
                  f"workers; results stream as each target finishes...{Style.RESET_ALL}", flush=True)
            with ThreadPoolExecutor(max_workers=min(args.concurrency, total)) as pool:
                futmap = {pool.submit(scan_one, it): it for it in indexed}
                for fut in as_completed(futmap):
                    idx, target = futmap[fut]
                    try:
                        res, buf = fut.result()
                    except Exception as e:
                        res = {'target': target, 'cves_tested': [], 'vulnerabilities': [],
                               'is_nextjs': False, 'version': None, 'error': str(e)}
                        buf = [f"{Fore.RED}[!] Error scanning {target}: {e}{Style.RESET_ALL}"]
                    done += 1
                    for line in buf:
                        print(line)
                    print(f"{Fore.CYAN}[*] Progress: {done}/{total} targets complete "
                          f"({target}){Style.RESET_ALL}", flush=True)
                    all_results.append(res)
        else:
            for it in indexed:
                res, buf = scan_one(it)
                for line in buf:
                    print(line)
                all_results.append(res)

        print(f"\n{Fore.CYAN}COMBINED RESULTS ({len(targets)} targets){Style.RESET_ALL}\n")
        
        total_vulnerable = sum(1 for r in all_results if len(r.get('vulnerabilities', [])) > 0)
        print(f"  {Fore.WHITE}Total Scanned:{Style.RESET_ALL}      {len(targets)}")
        print(f"  {Fore.RED}Vulnerable:{Style.RESET_ALL}        {total_vulnerable}")
        print(f"  {Fore.GREEN}Secure:{Style.RESET_ALL}            {len(targets) - total_vulnerable}")
        
        if total_vulnerable > 0:
            print(f"\n{Fore.RED}Vulnerable Targets:{Style.RESET_ALL}")
            for result in all_results:
                if len(result.get('vulnerabilities', [])) > 0:
                    print(f"  • {result['target']} ({len(result['vulnerabilities'])} CVE)")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] Combined results saved to: {args.output}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

