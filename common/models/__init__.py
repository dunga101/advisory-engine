from common.db import Base
from common.models.advisory import Advisory, AdvisoryCve, AdvisoryGuidance, AdvisoryRevisionHistory
from common.models.cve import Cve, CveRevisionHistory
from common.models.field_report import FieldReport
from common.models.patch_verdict import PatchVerdictHistory
from common.models.platform_reliability import PlatformReliabilityNote
from common.models.product import AdvisoryProductAffected, Product
from common.models.windows_update import WindowsUpdate

__all__ = [
    "Base",
    "Advisory",
    "AdvisoryCve",
    "AdvisoryGuidance",
    "AdvisoryRevisionHistory",
    "Cve",
    "CveRevisionHistory",
    "FieldReport",
    "PatchVerdictHistory",
    "PlatformReliabilityNote",
    "AdvisoryProductAffected",
    "Product",
    "WindowsUpdate",
]
