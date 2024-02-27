from graphene_sqlalchemy import SQLAlchemyObjectType
from rotas.arepo.arepo.models.bf import OperationModel, PhaseModel, BFClassModel


class Operation(SQLAlchemyObjectType):
    class Meta:
        model = OperationModel
        use_connection = True


class Phase(SQLAlchemyObjectType):
    class Meta:
        model = PhaseModel
        use_connection = True


class BFClass(SQLAlchemyObjectType):
    class Meta:
        model = BFClassModel
        use_connection = True
