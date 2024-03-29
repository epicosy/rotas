import graphene

from sqlalchemy import desc
from graphene.types.objecttype import ObjectType

from arepo.models.common.vulnerability import VulnerabilityCWEModel
from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability, VulnerabilityModel, Reference, VulnerabilityCWE

from rotas.objects.sqlalchemy.git import Commit, CommitModel, Repository, RepositoryModel
from rotas.objects.sqlalchemy.common.weakness import CWE, CWEModel
from rotas.objects.sqlalchemy.common.platform import ProductType, Product, ProductModel

from rotas.objects.sqlalchemy.data import Dataset, DatasetModel, Profile
from rotas.objects.sqlalchemy.code import Function, FunctionModel

from rotas.objects.graphene.helpers.types import LinkCount, LinkCountValueObject, Stats, StatsValueObject
# TODO: To be added MethodBoundary


class EntityQuery(ObjectType):
    cwes = graphene.List(lambda: CWE, id=graphene.ID(), exists=graphene.Boolean())
    vulnerability = graphene.Field(lambda: Vulnerability, vul_id=graphene.ID())
    vulnerabilities = graphene.List(lambda: Vulnerability, id=graphene.ID(), first=graphene.Int(), skip=graphene.Int(),
                                    last=graphene.Int())
    product_types = graphene.List(lambda: ProductType)
    commit = graphene.Field(lambda: Commit, id=graphene.ID())
    repository = graphene.Field(lambda: Repository, id=graphene.ID())
    repositories = graphene.List(Repository)
    product = graphene.Field(Product, id=graphene.ID())
    dataset = graphene.Field(lambda: Dataset, id=graphene.ID())
    datasets = graphene.List(lambda: Dataset)
    profiles = graphene.List(lambda: Profile)
    stats = graphene.Field(Stats)
    links = graphene.List(LinkCount)
    # TODO: not yet part of the schema
    # functions = graphene.List(lambda: MethodBoundary, file_id=graphene.String())

    @staticmethod
    def resolve_cwes(parent, info, cwe_id: int = None, exists: bool = False):
        query = CWE.get_query(info)

        if cwe_id:
            query = query.filter(CWEModel.id == cwe_id)

        if exists:
            # return CWEs that have vulnerabilities associated
            query = query.join(VulnerabilityCWEModel)

        return query.order_by('id').all()

    @staticmethod
    def resolve_vulnerability(parent, info, vul_id: str):
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id == vul_id).first()

    @staticmethod
    async def resolve_vulnerabilities(parent, info, id=None, first: int = None, skip: int = None, last: int = None, **kwargs):
        query = Vulnerability.get_query(info).order_by(desc(VulnerabilityModel.published_date))

        if id:
            return query.filter(VulnerabilityModel.id == id)
        query = query.all()

        if skip:
            query = query[skip:]

        if first:
            query = query[:first]

        elif last:
            query = query[:last]

        return query

    def resolve_product_types(self, info):
        return ProductType.get_query(info).all()

    def resolve_commit(self, info, id: str):
        return Commit.get_query(info).filter(CommitModel.id == id).first()

    def resolve_repository(self, info, id):
        return Repository.get_query(info).filter(RepositoryModel.id == id).join(CommitModel).first()

    def resolve_repositories(self, info):
        return Repository.get_query(info).all()

    def resolve_product(self, info, id):
        return Product.get_query(info).filter(ProductModel.id == id).first()

    def resolve_dataset(self, info, id):
        return Dataset.get_query(info).filter(DatasetModel.id == id).first()

    def resolve_datasets(self, info):
        return Dataset.get_query(info).all()

    def resolve_functions(self, info, file_id: str):
        return Function.get_query(info).filter_by(commit_file_id=file_id).order_by(FunctionModel.start).all()

    def resolve_profiles(self, info):
        return Profile.get_query(info).all()

    @staticmethod
    def resolve_stats(parent, info):
        total = Vulnerability.get_query(info).count()
        references = Reference.get_query(info).count()
        labeled = VulnerabilityCWE.get_query(info).count()
        commits = Commit.get_query(info).count()

        return StatsValueObject(total, labeled, references, commits)

    @staticmethod
    def resolve_links(parent, info):
        # TODO: refactor, is slow and this approach does not make sense
        cwe_ids = CWE.get_query(info).all()
        mapping = {}

        for cwe in cwe_ids:
            cwe_counts = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.cwe_id == cwe.id).count()

            if cwe_counts < 1:
                continue

            if len(cwe.bf_classes) != 1:
                continue

            if cwe.bf_classes[0].name == "None":
                continue

            if len(cwe.phases) != 1:
                continue

            link_name = f"{cwe.bf_classes[0].name} - {cwe.phases[0].name}"

            if link_name not in mapping:
                mapping[link_name] = LinkCount(cwe.bf_classes[0].name, cwe.phases[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

            if len(cwe.operations) != 1:
                continue

            link_name = f"{cwe.phases[0].name} - {cwe.operations[0].name}"

            if link_name not in mapping:
                mapping[link_name] = LinkCount(cwe.phases[0].name, cwe.operations[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

        return list(mapping.values())
