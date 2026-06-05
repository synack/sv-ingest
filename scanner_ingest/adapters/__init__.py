from .tenable_sc import TenableSCAdapter
from .cisa import CISAAdapter
from .qualys import QualysAdapter
from .generic import GenericAdapter
from .sast import SASTAdapter
from .sca import SCAAdapter

ADAPTER_REGISTRY: dict[str, type] = {
    "tenable_sc": TenableSCAdapter,
    "cisa":       CISAAdapter,
    "qualys":     QualysAdapter,
    "generic":    GenericAdapter,
    "opus-sast":  SASTAdapter,
    "opus-sca":   SCAAdapter,
}


def get_adapter(source_type: str, source_id: str, config: dict):
    cls = ADAPTER_REGISTRY.get(source_type)
    if cls is None:
        raise ValueError(f"Unknown source type '{source_type}'. Valid: {list(ADAPTER_REGISTRY)}")
    return cls(source_id=source_id, config=config)
