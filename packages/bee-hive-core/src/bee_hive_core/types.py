"""Core types for Bee-Hive network"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, Literal
from datetime import datetime


class ResponseSchema(BaseModel):
    """Base class for response schemas"""
    pass


class IntegerResponse(ResponseSchema):
    """Simple integer response (default for now)"""
    value: int = Field(..., description="Integer result value")


class Computation(BaseModel):
    """Core computation object shared across flower and nectar"""

    comp_id: str = Field(..., description="Unique computation ID")
    query: str = Field(..., description="Computation query/prompt")
    proposer: str = Field(..., description="Node that proposed computation")
    aggregators: list[str] = Field(..., description="Heavy nodes for aggregation")
    targets: list[str] = Field(..., description="Target nodes to execute")
    deadline: int = Field(..., description="Deadline in seconds")
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Response schema specification
    response_schema: Literal["integer"] = Field(
        default="integer",
        description="Response schema type (currently only 'integer' supported)"
    )


class ComputationResult(BaseModel):
    """Result of computation execution"""

    comp_id: str
    result: Optional[IntegerResponse] = None
    status: str = Field(..., description="success | error | timeout")
    error: Optional[str] = None
    execution_time: Optional[float] = None

    @property
    def value(self) -> Optional[int]:
        """Convenience property to extract integer value"""
        return self.result.value if self.result else None
