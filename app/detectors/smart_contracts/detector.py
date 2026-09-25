"""
Smart Contract Vulnerability Detector
Detects vulnerabilities in Solidity, Vyper, and other smart contract languages
"""
import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from app.detectors.base import Detector, Endpoint, Finding, Validator


class ContractLanguage(Enum):
    SOLIDITY = "solidity"
    VYPER = "vyper"
    RUST = "rust"  # Solana/Substrate
    MOVE = "move"  # Aptos/Sui
    GO = "go"      # Chaincode


@dataclass
class ContractSource:
    address: str
    source_code: str
    language: ContractLanguage
    compiler_version: str = ""
    abi: List[Dict] = field(default_factory=list)
    bytecode: str = ""


@dataclass
class VulnerabilityPattern:
    id: str
    name: str
    severity: str  # critical, high, medium, low, info
    pattern: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cwe: str = ""


# Comprehensive vulnerability patterns based on SWC Registry, ConsenSys Diligence, Trail of Bits
SOLIDITY_PATTERNS = [
    # Reentrancy
    VulnerabilityPattern(
        id="SWC-107",
        name="Reentrancy",
        severity="critical",
        pattern=r"(?:\.call\{value:|\.send\(|\.transfer\()",
        description="External call to untrusted contract before state changes - allows reentrancy attacks",
        remediation="Use checks-effects-interactions pattern. Use ReentrancyGuard. Pull payments instead of push.",
        references=["https://swcregistry.io/docs/SWC-107", "https://consensys.net/diligence/blog/2019/09/reentrancy-attacks/"],
        cwe="CWE-841"
    ),
    
    # Unchecked external call return value
    VulnerabilityPattern(
        id="SWC-104",
        name="Unchecked External Call Return Value",
        severity="high",
        pattern=r"(?:\.call\(|\.delegatecall\(|\.staticcall\(|\.send\()",
        description="Return value of external call not checked - failure may go unnoticed",
        remediation="Always check return values. Use require(success, 'message'). Use OpenZeppelin's Address library.",
        references=["https://swcregistry.io/docs/SWC-104"],
        cwe="CWE-252"
    ),
    
    # Integer overflow/underflow (pre-0.8.0)
    VulnerabilityPattern(
        id="SWC-101",
        name="Integer Overflow/Underflow",
        severity="critical",
        pattern=r"(?:\+\+|\-\-|\+=|\-=|\*=|/=|%=)",
        description="Arithmetic operations without overflow checks (Solidity < 0.8.0)",
        remediation="Use Solidity >= 0.8.0 with built-in checks. Use SafeMath for older versions.",
        references=["https://swcregistry.io/docs/SWC-101"],
        cwe="CWE-190"
    ),
    
    # Delegatecall to untrusted contract
    VulnerabilityPattern(
        id="SWC-112",
        name="Delegatecall to Untrusted Contract",
        severity="critical",
        pattern=r"\.delegatecall\(",
        description="Delegatecall to user-supplied address allows arbitrary code execution in caller's context",
        remediation="Avoid delegatecall to untrusted addresses. Use library pattern. Validate target address.",
        references=["https://swcregistry.io/docs/SWC-112"],
        cwe="CWE-826"
    ),
    
    # Tx.origin authentication
    VulnerabilityPattern(
        id="SWC-115",
        name="Tx.origin Authentication",
        severity="high",
        pattern=r"tx\.origin",
        description="Using tx.origin for authentication allows phishing attacks",
        remediation="Use msg.sender instead of tx.origin for authorization.",
        references=["https://swcregistry.io/docs/SWC-115"],
        cwe="CWE-287"
    ),
    
    # Unprotected selfdestruct
    VulnerabilityPattern(
        id="SWC-106",
        name="Unprotected Selfdestruct",
        severity="critical",
        pattern=r"selfdestruct\(",
        description="Selfdestruct accessible to unauthorized users - can destroy contract",
        remediation="Add access control (onlyOwner). Use timelock. Consider proxy pattern instead.",
        references=["https://swcregistry.io/docs/SWC-106"],
        cwe="CWE-284"
    ),
    
    # Weak randomness
    VulnerabilityPattern(
        id="SWC-120",
        name="Weak Randomness",
        severity="high",
        pattern=r"(?:block\.timestamp|block\.number|block\.difficulty|blockhash|block\.coinbase|block\.gaslimit)",
        description="Using block variables for randomness - miners can manipulate",
        remediation="Use Chainlink VRF. Use commit-reveal scheme. Use external randomness oracle.",
        references=["https://swcregistry.io/docs/SWC-120"],
        cwe="CWE-338"
    ),
    
    # Timestamp dependence
    VulnerabilityPattern(
        id="SWC-116",
        name="Timestamp Dependence",
        severity="medium",
        pattern=r"block\.timestamp",
        description="Contract logic depends on block.timestamp - miners can manipulate within ~15 seconds",
        remediation="Avoid timestamp for critical logic. Use block numbers for time bounds. Allow tolerance.",
        references=["https://swcregistry.io/docs/SWC-116"],
        cwe="CWE-829"
    ),
    
    # Short address attack
    VulnerabilityPattern(
        id="SWC-123",
        name="Short Address Attack",
        severity="medium",
        pattern=r"\.transferFrom\(|\.approve\(",
        description="Missing address length validation allows short address padding attack",
        remediation="Validate address length: require(_addr.length == 20). Use OpenZeppelin's Address library.",
        references=["https://swcregistry.io/docs/SWC-123"],
        cwe="CWE-20"
    ),
    
    # Missing zero address check
    VulnerabilityPattern(
        id="SWC-132",
        name="Missing Zero Address Validation",
        severity="medium",
        pattern=r"(?:address\(0x0\)|address\(0\))",
        description="Operations allowing zero address - can lock tokens or break logic",
        remediation="Add require(_addr != address(0)). Use OpenZeppelin's Address library.",
        references=["https://swcregistry.io/docs/SWC-132"],
        cwe="CWE-20"
    ),
    
    # Floating pragma
    VulnerabilityPattern(
        id="SWC-103",
        name="Floating Pragma",
        severity="low",
        pattern=r"pragma solidity \^",
        description="Floating pragma allows compilation with different compiler versions",
        remediation="Lock pragma to specific version: pragma solidity 0.8.19;",
        references=["https://swcregistry.io/docs/SWC-103"],
        cwe="CWE-664"
    ),
    
    # Uninitialized storage pointer
    VulnerabilityPattern(
        id="SWC-109",
        name="Uninitialized Storage Pointer",
        severity="high",
        pattern=r"(?:struct\s+\w+\s*\{[^}]*\})",
        description="Local storage variable not initialized - points to slot 0, overwriting state",
        remediation="Initialize all local storage variables. Use memory keyword for temporary data.",
        references=["https://swcregistry.io/docs/SWC-109"],
        cwe="CWE-824"
    ),
    
    # Arbitrary storage write
    VulnerabilityPattern(
        id="SWC-124",
        name="Arbitrary Storage Write",
        severity="critical",
        pattern=r"(?:storage\s+\w+\s*=|mapping\s*\(.*\)\s+\w+)",
        description="User input used directly as storage index - can overwrite arbitrary storage slots",
        remediation="Validate all user inputs used as indices. Use internal mappings with access control.",
        references=["https://swcregistry.io/docs/SWC-124"],
        cwe="CWE-123"
    ),
    
    # DoS with block gas limit
    VulnerabilityPattern(
        id="SWC-128",
        name="DoS with Block Gas Limit",
        severity="medium",
        pattern=r"(?:for\s*\(|while\s*\()",
        description="Unbounded loops over user-controlled arrays - can exceed block gas limit",
        remediation="Use pull-over-push pattern. Limit loop iterations. Use pagination for large arrays.",
        references=["https://swcregistry.io/docs/SWC-128"],
        cwe="CWE-400"
    ),
    
    # Right-to-left override
    VulnerabilityPattern(
        id="SWC-130",
        name="Right-to-Left Override",
        severity="low",
        pattern=r"[\u202E\u202D]",
        description="RTLO character in source code can visually reorder code",
        remediation="Scan source for RTL override characters. Use IDE with Unicode detection.",
        references=["https://swcregistry.io/docs/SWC-130"],
        cwe="CWE-451"
    ),
    
    # Missing events for sensitive operations
    VulnerabilityPattern(
        id="SWC-129",
        name="Missing Events for Sensitive Operations",
        severity="low",
        pattern=r"(?:transfer|mint|burn|approve|setOwner|changeAdmin)",
        description="Sensitive state changes without event emission - breaks off-chain monitoring",
        remediation="Emit events for all sensitive operations: Transfer, Approval, OwnershipTransferred, etc.",
        references=["https://swcregistry.io/docs/SWC-129"],
        cwe="CWE-778"
    ),
    
    # Shadowing state variables
    VulnerabilityPattern(
        id="SWC-119",
        name="Shadowing State Variables",
        severity="low",
        pattern=r"(?:contract\s+\w+\s*\{[^}]*)\b(\w+)\b.*\b\1\b",
        description="Local variable shadows state variable - causes confusion and bugs",
        remediation="Use different names for local vs state variables. Enable compiler warnings.",
        references=["https://swcregistry.io/docs/SWC-119"],
        cwe="CWE-563"
    ),
    
    # Dangerous use of assembly
    VulnerabilityPattern(
        id="SWC-133",
        name="Dangerous Assembly Usage",
        severity="high",
        pattern=r"assembly\s*\{",
        description="Inline assembly bypasses Solidity safety checks - use with extreme caution",
        remediation="Avoid assembly unless necessary. If used, add extensive comments and testing.",
        references=["https://swcregistry.io/docs/SWC-133"],
        cwe="CWE-250"
    ),
    
    # Unencrypted private data
    VulnerabilityPattern(
        id="SWC-136",
        name="Unencrypted Private Data On-Chain",
        severity="medium",
        pattern=r"private\s+(?:bytes|string|uint|address)",
        description="Private variables are visible on-chain - only restricts contract access, not visibility",
        remediation="Don't store secrets on-chain. Use encryption off-chain. Use commit-reveal for secrets.",
        references=["https://swcregistry.io/docs/SWC-136"],
        cwe="CWE-312"
    ),
    
    # ERC20/ERC721 specific
    VulnerabilityPattern(
        id="ERC20-001",
        name="ERC20: Missing Return Value",
        severity="high",
        pattern=r"function transfer\(|function approve\(",
        description="ERC20 transfer/approve functions must return bool - missing return breaks compatibility",
        remediation="Add 'returns (bool)' and return true on success.",
        references=["https://eips.ethereum.org/EIPS/eip-20"],
        cwe="CWE-393"
    ),
    
    # Access control missing
    VulnerabilityPattern(
        id="AC-001",
        name="Missing Access Control",
        severity="critical",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s*\{",
        description="Public/external function without access control modifier",
        remediation="Add onlyOwner, onlyRole, or custom modifiers. Use OpenZeppelin AccessControl.",
        references=["https://docs.openzeppelin.com/contracts/4.x/access-control"],
        cwe="CWE-284"
    ),
    
    # Flash loan vulnerability
    VulnerabilityPattern(
        id="FL-001",
        name="Flash Loan Vulnerability",
        severity="high",
        pattern=r"(?:getPrice|priceOracle|calculatePrice|getReserves)",
        description="Price oracle manipulation via flash loans - single price source without TWAP",
        remediation="Use TWAP oracles. Use multiple price sources. Add manipulation detection.",
        references=["https://consensys.net/diligence/blog/2020/12/flash-loan-attacks/"],
        cwe="CWE-829"
    ),
]


VYPER_PATTERNS = [
    VulnerabilityPattern(
        id="VYPER-001",
        name="Vyper: Missing Input Validation",
        severity="high",
        pattern=r"@external\s+def\s+\w+\(",
        description="External function without input validation",
        remediation="Add assert/require statements for all inputs. Validate ranges and formats.",
        references=["https://vyper.readthedocs.io/en/stable/security-considerations.html"],
        cwe="CWE-20"
    ),
    VulnerabilityPattern(
        id="VYPER-002",
        name="Vyper: Reentrancy via Raw Call",
        severity="critical",
        pattern=r"raw_call\(|raw_log\(",
        description="Raw calls bypass Vyper's reentrancy protection",
        remediation="Avoid raw_call. Use standard interfaces. Add reentrancy guards.",
        references=["https://vyper.readthedocs.io/en/stable/security-considerations.html"],
        cwe="CWE-841"
    ),
]


RUST_PATTERNS = [
    # Solana/Substrate
    VulnerabilityPattern(
        id="RUST-001",
        name="Solana: Missing Account Validation",
        severity="critical",
        pattern=r"AccountInfo|UncheckedAccount",
        description="Account not validated - can pass arbitrary accounts",
        remediation="Use Anchor's Account validation. Check owner, signer, writable, executable.",
        references=["https://docs.anchor-lang.com/anchor-references/accounts"],
        cwe="CWE-284"
    ),
    VulnerabilityPattern(
        id="RUST-002",
        name="Solana: Missing Signer Check",
        severity="critical",
        pattern=r"Signer\b",
        description="Account marked as Signer but not verified",
        remediation="Use #[account(signer)] constraint. Verify key matches expected.",
        references=["https://docs.anchor-lang.com/anchor-references/accounts"],
        cwe="CWE-287"
    ),
    VulnerabilityPattern(
        id="RUST-003",
        name="Solana: Integer Overflow",
        severity="high",
        pattern=r"(?:\.checked_add\(|\.checked_sub\(|\.checked_mul\(|\.saturating_)",
        description="Arithmetic without checked/saturating operations",
        remediation="Use checked_*, saturating_*, or wrapping_* methods explicitly.",
        references=["https://doc.rust-lang.org/std/primitive.u64.html"],
        cwe="CWE-190"
    ),
    VulnerabilityPattern(
        id="RUST-004",
        name="Solana: CPI Reentrancy",
        severity="critical",
        pattern=r"invoke_signed\(|invoke\(",
        description="Cross-program invocation without reentrancy protection",
        remediation="Use reentrancy guards. Check program state after CPI. Use atomic operations.",
        references=["https://solana.com/docs/core/cpi"],
        cwe="CWE-841"
    ),
    VulnerabilityPattern(
        id="RUST-005",
        name="Solana: PDA Seed Validation",
        severity="high",
        pattern=r"find_program_address|create_program_address",
        description="PDA seeds not validated - can derive unauthorized addresses",
        remediation="Validate all PDA seeds. Use bump seeds. Check program ownership.",
        references=["https://solana.com/docs/core/pda"],
        cwe="CWE-287"
    ),
]


MOVE_PATTERNS = [
    VulnerabilityPattern(
        id="MOVE-001",
        name="Move: Missing Resource Protection",
        severity="high",
        pattern=r"struct\s+\w+\s*has\s+key",
        description="Resource without proper access control",
        remediation="Use signer capability. Add witness patterns. Validate caller.",
        references=["https://move-language.github.io/move/security/"],
        cwe="CWE-284"
    ),
    VulnerabilityPattern(
        id="MOVE-002",
        name="Move: Unbounded Loop",
        severity="medium",
        pattern=r"while\s+\(|loop\s+\{",
        description="Unbounded loop can exceed gas limits",
        remediation="Add loop bounds. Use for loops with range. Limit iterations.",
        references=["https://move-language.github.io/move/security/"],
        cwe="CWE-835"
    ),
]


GO_PATTERNS = [
    # Chaincode
    VulnerabilityPattern(
        id="GO-001",
        name="Fabric: Missing Transient Data",
        severity="medium",
        pattern=r"GetState\(|PutState\(",
        description="Private data stored in world state instead of transient",
        remediation="Use transient map for private data. Use collections for private data.",
        references=["https://hyperledger-fabric.readthedocs.io/en/latest/private_data/private_data.html"],
        cwe="CWE-312"
    ),
    VulnerabilityPattern(
        id="GO-002",
        name="Fabric: Missing Endorsement Policy",
        severity="high",
        pattern=r"Init\(|Invoke\(",
        description="Chaincode without explicit endorsement policy",
        remediation="Define endorsement policy at deployment. Use state-based endorsement.",
        references=["https://hyperledger-fabric.readthedocs.io/en/latest/endorsement-policies.html"],
        cwe="CWE-284"
    ),
]


class SmartContractDetector(Detector):
    name = "smart_contract"
    vuln_class = "Smart Contract Vulnerability"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Blockchain > Smart Contract Vulnerability"

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self.contract_sources: Dict[str, ContractSource] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for faster matching"""
        self.compiled_patterns = {}
        for pattern in SOLIDITY_PATTERNS:
            self.compiled_patterns[pattern.id] = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
        for pattern in VYPER_PATTERNS:
            self.compiled_patterns[pattern.id] = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
        for pattern in RUST_PATTERNS:
            self.compiled_patterns[pattern.id] = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
        for pattern in MOVE_PATTERNS:
            self.compiled_patterns[pattern.id] = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
        for pattern in GO_PATTERNS:
            self.compiled_patterns[pattern.id] = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)

    def applies_to(self, endpoint: Endpoint) -> bool:
        # Check if endpoint is a blockchain-related endpoint
        url = endpoint.url.lower()
        blockchain_indicators = [
            "etherscan", "bscscan", "polygonscan", "arbiscan", "optimistic",
            "solscan", "explorer.solana", "subscan", "polkadot",
            "cosmoscan", "mintscan", "viewblock", "near",
            "rpc", "alchemy", "infura", "quicknode", "chainstack",
            "hardhat", "foundry", "truffle", "brownie",
            "anchor", "solana", "web3", "ethers", "viem",
        ]
        return any(ind in url for ind in blockchain_indicators) or \
               endpoint.headers.get("content-type", "").startswith("application/json") and \
               any(k in str(endpoint.params) for k in ["abi", "bytecode", "source", "contract"])

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        # Try to extract contract source code
        sources = await self._extract_contract_sources(endpoint)
        
        for address, source in sources.items():
            contract_findings = await self._analyze_contract(source)
            findings.extend(contract_findings)

        # Also analyze bytecode if available
        bytecode_findings = await self._analyze_bytecode(endpoint)
        findings.extend(bytecode_findings)

        return findings

    async def _extract_contract_sources(self, endpoint: Endpoint) -> Dict[str, ContractSource]:
        """Extract contract source from various sources"""
        sources = {}
        
        # Try Etherscan-style API
        if "etherscan" in endpoint.url or "api." in endpoint.url:
            source = await self._fetch_from_etherscan_api(endpoint)
            if source:
                sources[source.address] = source
        
        # Try direct source parameter
        for param in endpoint.params:
            value = endpoint.get_param_value(param) or ""
            if value.startswith("0x") and len(value) > 40:
                # Likely bytecode
                sources[value[:42]] = ContractSource(
                    address=value[:42],
                    source_code="",
                    language=ContractLanguage.SOLIDITY,
                    bytecode=value
                )
            elif "pragma solidity" in value or "contract " in value:
                # Source code
                sources["inline"] = ContractSource(
                    address="inline",
                    source_code=value,
                    language=ContractLanguage.SOLIDITY
                )
            elif "#[program]" in value or "use anchor_lang" in value:
                sources["inline"] = ContractSource(
                    address="inline",
                    source_code=value,
                    language=ContractLanguage.RUST
                )
        
        return sources

    async def _fetch_from_etherscan_api(self, endpoint: Endpoint) -> Optional[ContractSource]:
        """Fetch contract source from Etherscan-like API"""
        try:
            # Extract address from URL or params
            address = None
            for param in endpoint.params:
                val = endpoint.get_param_value(param) or ""
                if re.match(r"^0x[a-fA-F0-9]{40}$", val):
                    address = val
                    break
            
            if not address:
                return None
            
            # Try to get source code
            api_url = endpoint.url
            if "apikey" not in api_url:
                api_url += "&apikey=YourApiKeyToken"  # Would need real API key
            
            resp = await self.http_client.get(api_url, timeout=30)
            if resp.status_code != 200:
                return None
            
            data = resp.json()
            if data.get("status") == "1" and data.get("result"):
                result = data["result"][0] if isinstance(data["result"], list) else data["result"]
                return ContractSource(
                    address=address,
                    source_code=result.get("SourceCode", ""),
                    language=ContractLanguage.SOLIDITY,
                    compiler_version=result.get("CompilerVersion", ""),
                    abi=json.loads(result.get("ABI", "[]")) if result.get("ABI") else [],
                    bytecode=result.get("Bytecode", "")
                )
        except Exception:
            pass
        return None

    async def _analyze_contract(self, source: ContractSource) -> List[Finding]:
        """Analyze contract source code for vulnerabilities"""
        findings = []
        
        if not source.source_code and not source.bytecode:
            return findings
        
        patterns = self._get_patterns_for_language(source.language)
        
        for pattern in patterns:
            compiled = self.compiled_patterns.get(pattern.id)
            if not compiled:
                continue
            
            code_to_scan = source.source_code if source.source_code else source.bytecode
            matches = list(compiled.finditer(code_to_scan))
            
            if matches:
                # For critical patterns, verify more carefully
                if pattern.severity in ["critical", "high"]:
                    verified = await self._verify_vulnerability(source, pattern, matches, code_to_scan)
                    if not verified:
                        continue
                
                finding = self._make_finding(
                    endpoint=Endpoint(url=f"contract:{source.address}", method="ANALYZE"),
                    param=pattern.id,
                    confidence="confirmed" if pattern.severity in ["critical", "high"] else "suspected",
                    evidence={
                        "pattern_id": pattern.id,
                        "pattern_name": pattern.name,
                        "matches": [{"line": self._get_line_number(code_to_scan, m.start()), "context": m.group()} for m in matches[:5]],
                        "contract_address": source.address,
                        "language": source.language.value,
                        "compiler_version": source.compiler_version,
                    },
                    summary=f"{pattern.name} ({pattern.id}) in {source.language.value} contract {source.address[:10]}...",
                    description=pattern.description,
                    steps_to_reproduce=(
                        f"1. Review contract at {source.address}\n"
                        f"2. Locate pattern: {pattern.pattern}\n"
                        f"3. Verify vulnerability context\n"
                        f"4. Exploit if confirmed"
                    ),
                    impact=self._get_impact_for_severity(pattern.severity),
                    remediation=pattern.remediation,
                )
                findings.append(finding)
        
        return findings

    def _get_patterns_for_language(self, language: ContractLanguage) -> List[VulnerabilityPattern]:
        if language == ContractLanguage.SOLIDITY:
            return SOLIDITY_PATTERNS
        elif language == ContractLanguage.VYPER:
            return VYPER_PATTERNS
        elif language == ContractLanguage.RUST:
            return RUST_PATTERNS
        elif language == ContractLanguage.MOVE:
            return MOVE_PATTERNS
        elif language == ContractLanguage.GO:
            return GO_PATTERNS
        return []

    def _get_line_number(self, code: str, position: int) -> int:
        return code[:position].count('\n') + 1

    async def _verify_vulnerability(self, source: ContractSource, pattern: VulnerabilityPattern, 
                                     matches: List, code: str) -> bool:
        """Additional verification for critical vulnerabilities"""
        # Context-aware verification
        for match in matches:
            line_start = code.rfind('\n', 0, match.start()) + 1
            line_end = code.find('\n', match.end())
            if line_end == -1:
                line_end = len(code)
            context = code[line_start:line_end]
            
            # Skip if in comments
            if context.strip().startswith("//") or context.strip().startswith("/*") or context.strip().startswith("*"):
                continue
            
            # Skip if in test files
            if "test" in context.lower() or "mock" in context.lower():
                continue
            
            # Pattern-specific verification
            if pattern.id == "SWC-107":  # Reentrancy
                # Check if state changes before call
                before_call = code[:match.start()][-500:]
                if "=" in before_call and not re.search(r"require\(|assert\(|revert\(", before_call):
                    return True
            elif pattern.id == "SWC-104":  # Unchecked call
                # Check if return value is used
                after_call = code[match.end():match.end()+100]
                if not re.search(r"require\(|assert\(|if\s*\(", after_call):
                    return True
            elif pattern.id == "SWC-112":  # Delegatecall
                # Check if target is user-controlled
                return True  # Always flag delegatecall
            else:
                return True
        return False

    def _get_impact_for_severity(self, severity: str) -> str:
        impacts = {
            "critical": "Can lead to complete contract compromise, fund theft, or contract destruction.",
            "high": "Can lead to significant fund loss, unauthorized access, or logic bypass.",
            "medium": "Can cause denial of service, logic errors, or information leakage.",
            "low": "Code quality issue that could lead to vulnerabilities in future changes.",
            "info": "Informational - best practice violation."
        }
        return impacts.get(severity, "Impact varies based on context.")

    async def _analyze_bytecode(self, endpoint: Endpoint) -> List[Finding]:
        """Analyze contract bytecode for vulnerabilities"""
        findings = []
        
        # Check if we have bytecode
        bytecode = None
        for param in endpoint.params:
            value = endpoint.get_param_value(param) or ""
            if value.startswith("0x") and len(value) > 100:
                bytecode = value
                break
        
        if not bytecode:
            return findings
        
        # Decompile bytecode patterns
        bytecode_patterns = [
            (r"3d602d80600a3d3981f336", "Constructor not properly initialized"),
            (r"36600057", "Unprotected selfdestruct"),
            (r"f300", "Potential reentrancy (CALL after SSTORE)"),
        ]
        
        for pattern, description in bytecode_patterns:
            if re.search(pattern, bytecode, re.IGNORECASE):
                findings.append(self._make_finding(
                    endpoint=Endpoint(url=endpoint.url, method="BYTECODE"),
                    param="bytecode_analysis",
                    confidence="suspected",
                    evidence={
                        "bytecode_pattern": pattern,
                        "description": description,
                        "bytecode_preview": bytecode[:200],
                    },
                    summary=f"Bytecode Analysis: {description}",
                    description=f"Bytecode pattern {pattern} detected: {description}",
                    steps_to_reproduce="1. Decompile bytecode\n2. Analyze control flow\n3. Verify vulnerability",
                    impact="Bytecode analysis reveals potential vulnerabilities not visible in source.",
                    remediation="Verify source code matches bytecode. Use formal verification tools.",
                ))
        
        return findings

    async def analyze_contract_file(self, file_path: str) -> List[Finding]:
        """Analyze a local contract file"""
        try:
            with open(file_path, 'r') as f:
                source_code = f.read()
            
            # Detect language
            language = ContractLanguage.SOLIDITY
            if file_path.endswith(".vy"):
                language = ContractLanguage.VYPER
            elif file_path.endswith(".rs"):
                language = ContractLanguage.RUST
            elif file_path.endswith(".move"):
                language = ContractLanguage.MOVE
            elif file_path.endswith(".go"):
                language = ContractLanguage.GO
            
            source = ContractSource(
                address=file_path,
                source_code=source_code,
                language=language
            )
            
            return await self._analyze_contract(source)
        except Exception:
            return []


# Export for easy import
__all__ = [
    'SmartContractDetector',
    'ContractSource',
    'ContractLanguage',
    'VulnerabilityPattern',
    'SOLIDITY_PATTERNS',
    'VYPER_PATTERNS',
    'RUST_PATTERNS',
    'MOVE_PATTERNS',
    'GO_PATTERNS',
]