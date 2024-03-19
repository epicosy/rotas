from graphene_sqlalchemy import SQLAlchemyObjectType

from arepo.models.vcs.symbol import FunctionModel


class Function(SQLAlchemyObjectType):
    class Meta:
        model = FunctionModel
        use_connection = True
