import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType
from rotas.arepo.arepo.models.common.weakness import (AbstractionModel, GroupingModel, CWEOperationModel, CWEPhaseModel,
                                                      CWEModel, CWEBFClassModel)

from rotas.arepo.arepo.models.bf import BFClassModel, PhaseModel, OperationModel
from rotas.objects.graphene.bf import Operation, Phase, BFClass


class Abstraction(SQLAlchemyObjectType):
    class Meta:
        model = AbstractionModel
        use_connection = True

    name = graphene.String()


class Grouping(SQLAlchemyObjectType):
    class Meta:
        model = GroupingModel
        use_connection = True


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


class CWE(SQLAlchemyObjectType):
    class Meta:
        model = CWEModel
        use_connection = True
        filter_fields = ["id"]

    id = graphene.Int()
    abstraction_id = graphene.Int()
    abstraction = graphene.String()
    operations = graphene.List(lambda: Operation, name=graphene.String())
    phases = graphene.List(lambda: Phase, name=graphene.String(), acronym=graphene.String())
    bf_classes = graphene.List(lambda: BFClass, name=graphene.String())

    def resolve_id(self, info):
        return self.id

    def resolve_abstraction_id(self, info):
        return self.abstraction_id

    def resolve_abstraction(self, info):
        query = Abstraction.get_query(info=info).filter(AbstractionModel.id == self.abstraction_id).first()

        if query:
            return query.name

        return None

    def resolve_operations(self, info, name=None):
        cwe_op_query = CWEOperation.get_query(info=info)
        cwe_op_query = cwe_op_query.filter(CWEOperationModel.cwe_id == self.id)

        ops = []
        ops_query = Operation.get_query(info=info)

        for cwe_op in cwe_op_query.all():
            ops_query = ops_query.filter(OperationModel.id == cwe_op.operation_id)

            if name:
                ops_query = ops_query.filter(OperationModel.name == name)

            if ops_query.first():
                ops.append(ops_query.first())

        return ops

    def resolve_phases(self, info):
        cwe_phase_query = CWEPhase.get_query(info=info).filter(CWEPhaseModel.cwe_id == self.id)
        phases = [el.phase_id for el in cwe_phase_query.all()]

        return Phase.get_query(info=info).filter(PhaseModel.id.in_(phases))

    def resolve_bf_class(self, info):
        cwe_bf_class_query = CWEBFClass.get_query(info=info).filter(CWEBFClassModel.cwe_id == self.id)
        bc_classes = [el.bf_class_id for el in cwe_bf_class_query.all()]

        return BFClass.get_query(info=info).filter(BFClassModel.id.in_(bc_classes)).all()
