import graphene

from graphene_sqlalchemy import SQLAlchemyObjectType

from rotas.arepo.arepo.models.data import (ProfileModel, ProfileCWEModel, DatasetVulnerabilityModel, WeaknessModel,
                                           DatasetModel)
from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability, VulnerabilityModel


class Profile(SQLAlchemyObjectType):
    class Meta:
        model = ProfileModel
        use_connection = True

    id = graphene.Int()
    name = graphene.String()

    def resolve_id(self, info):
        return self.id

    def resolve_name(self, info):
        return self.name


class ProfileCWE(SQLAlchemyObjectType):
    class Meta:
        model = ProfileCWEModel
        use_connection = True


class DatasetVulnerability(SQLAlchemyObjectType):
    class Meta:
        model = DatasetVulnerabilityModel
        use_connection = True


class Weakness(SQLAlchemyObjectType):
    class Meta:
        model = WeaknessModel
        use_connection = True

    id = graphene.Int()
    tuple = graphene.String()

    def resolve_id(self, info):
        return self.id

    def resolve_tuple(self, info):
        return self.tuple


class Dataset(SQLAlchemyObjectType):
    class Meta:
        model = DatasetModel
        use_connection = True

    id = graphene.Int()
    name = graphene.String()
    description = graphene.String()
    vulnerabilities = graphene.List(lambda: Vulnerability)
    size = graphene.Int()

    def resolve_vulnerabilities(self, info):
        vuln_ids = DatasetVulnerability.get_query(info).filter_by(dataset_id=self.id).all()
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id.in_([vuln.vulnerability_id for vuln in vuln_ids])).all()

    def resolve_id(self, info):
        return self.id

    def resolve_name(self, info):
        return self.name

    def resolve_description(self, info):
        return self.description

    def resolve_size(self, info):
        vuln_ids = DatasetVulnerability.get_query(info).filter_by(dataset_id=self.id).all()
        return len(vuln_ids)
