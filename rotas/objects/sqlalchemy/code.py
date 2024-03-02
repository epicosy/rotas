from graphene_sqlalchemy import SQLAlchemyObjectType

from arepo.models.code import LineModel, FunctionModel


class Line(SQLAlchemyObjectType):
    class Meta:
        model = LineModel
        use_connection = True


class Function(SQLAlchemyObjectType):
    class Meta:
        model = FunctionModel
        use_connection = True
