import graphene

from graphene_sqlalchemy import SQLAlchemyObjectType

from arepo.models.data import (ProfileModel, ProfileCWEModel, DatasetVulnerabilityModel, WeaknessModel, DatasetModel)
from arepo.models.git import CommitModel

from rotas.objects.graphene.helpers.types import GrapheneCount
from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability, VulnerabilityModel
from rotas.objects.sqlalchemy.git import Commit


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
    extensions = graphene.Field(lambda: GrapheneCount)
    cwes = graphene.List(lambda: GrapheneCount)

    @staticmethod
    async def resolve_cwes(parent, info):
        vuln_ids = DatasetVulnerability.get_query(info).filter_by(dataset_id=parent.id).all()
        vulns = (Vulnerability.get_query(info)
                 .filter(VulnerabilityModel.id.in_([vuln.vulnerability_id for vuln in vuln_ids])).all())
        cwe_counts = {}

        for v in vulns:
            for cwe in v.cwes:
                if cwe.id not in cwe_counts:
                    cwe_counts[cwe.id] = 1
                else:
                    cwe_counts[cwe.id] += 1

        return [GrapheneCount(key=k, value=v) for k, v in cwe_counts.items()]

    @staticmethod
    async def resolve_extensions(parent, info):
        vuln_ids = DatasetVulnerability.get_query(info).filter_by(dataset_id=parent.id).all()
        vulns = (Vulnerability.get_query(info)
                 .filter(VulnerabilityModel.id.in_([vuln.vulnerability_id for vuln in vuln_ids])).all())
        extension_counts = {}

        for v in vulns:
            for c in v.commits:
                for f in c.files:
                    if f.extension not in extension_counts:
                        extension_counts[f.extension] = 1
                    else:
                        extension_counts[f.extension] += 1

        return extension_counts

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
