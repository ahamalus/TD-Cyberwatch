from __future__ import annotations

from typing import Generic, TypeVar

from fastapi import Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class PageParams:
    def __init__(
        self,
        page: int = Query(1, ge=1, le=100000),
        page_size: int = Query(25, ge=1, le=200),
    ):
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def paginate(db: Session, query: Select, params: PageParams, mapper=None) -> dict:
    total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
    rows = db.execute(query.offset(params.offset).limit(params.page_size)).scalars().all()
    items = [mapper(r) for r in rows] if mapper else rows
    return {"items": items, "total": total, "page": params.page, "page_size": params.page_size}


class Message(BaseModel):
    message: str
