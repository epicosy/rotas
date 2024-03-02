from graphene_sqlalchemy import SQLAlchemyObjectType

from arepo.models.common.weakness import CWEOperationModel, CWEPhaseModel, CWEBFClassModel


class CWEOperation(SQLAlchemyObjectType):
    class Meta:
        model = CWEOperationModel
        use_connection = True


class CWEPhase(SQLAlchemyObjectType):
    class Meta:
        model = CWEPhaseModel
        use_connection = True


class CWEBFClass(SQLAlchemyObjectType):
    class Meta:
        model = CWEBFClassModel
        use_connection = True


