"""
Burp Suite-style Modules Package
Intruder, Repeater, Sequencer, Comparer, Extender
"""
from app.burp_modules.intruder import (
    Intruder,
    IntruderRequest,
    IntruderResult,
    IntruderPosition,
    AttackType,
    parse_burp_request,
)

from app.burp_modules.repeater import (
    Repeater,
    RepeaterRequest,
    RepeaterResponse,
    RepeaterHistoryEntry,
    TabType,
    add_auth_header,
    add_cookie_header,
    follow_redirects,
)

from app.burp_modules.sequencer import (
    Sequencer,
    TokenSample,
    EntropyAnalysis,
    analyze_jwt,
)

from app.burp_modules.comparer import (
    Comparer,
    DiffFormatter,
    DiffResult,
    DiffType,
)

from app.burp_modules.extender import (
    ExtensionBase,
    ExtensionContext,
    ExtensionManager,
    ExtensionMetadata,
    IntruderPayloadGenerator,
    ScannerCheck,
    SessionHandler,
    MacroEngine,
    VulnerabilityFinding,
    BuiltInPayloadGenerators,
    ExampleCustomCheck,
)

__all__ = [
    # Intruder
    'Intruder',
    'IntruderRequest',
    'IntruderResult',
    'IntruderPosition',
    'AttackType',
    'parse_burp_request',
    # Repeater
    'Repeater',
    'RepeaterRequest',
    'RepeaterResponse',
    'RepeaterHistoryEntry',
    'TabType',
    'add_auth_header',
    'add_cookie_header',
    'follow_redirects',
    # Sequencer
    'Sequencer',
    'TokenSample',
    'EntropyAnalysis',
    'analyze_jwt',
    # Comparer
    'Comparer',
    'DiffFormatter',
    'DiffResult',
    'DiffType',
    # Extender
    'ExtensionBase',
    'ExtensionContext',
    'ExtensionManager',
    'ExtensionMetadata',
    'IntruderPayloadGenerator',
    'ScannerCheck',
    'SessionHandler',
    'MacroEngine',
    'VulnerabilityFinding',
    'BuiltInPayloadGenerators',
    'ExampleCustomCheck',
]