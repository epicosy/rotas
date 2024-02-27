import graphene

from graphene.types.objecttype import ObjectType

from rotas.objects.sqlalchemy.common.weakness import CWE, CWEModel
from rotas.objects.sqlalchemy.common.platform import ProductType, Product, ProductModel
from rotas.objects.sqlalchemy.common.vulnerability import (Vulnerability, VulnerabilityModel, VulnerabilityCWEModel,
                                                           VulnerabilityCWE, Reference)

from rotas.objects.sqlalchemy.git import Commit, CommitModel, Repository, RepositoryModel
from rotas.objects.sqlalchemy.data import Dataset, DatasetModel, Profile
from rotas.objects.sqlalchemy.code import Function, FunctionModel
from rotas.objects.graphene.queries.counts import ProfileCount


class Position(ObjectType):
    line = graphene.Int()
    column = graphene.Int()


class MethodBoundary(ObjectType):
    name = graphene.String()
    start = graphene.Field(lambda: Position)
    end = graphene.Field(lambda: Position)
    code = graphene.List(graphene.String)


class Stats(ObjectType):
    total = graphene.Int()
    labeled = graphene.Int()
    references = graphene.Int()
    commits = graphene.Int()


class Link(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()


class EntityQuery(ObjectType):
    cwes = graphene.List(lambda: CWE, id=graphene.ID(), exists=graphene.Boolean())
    vulnerability = graphene.Field(lambda: Vulnerability, id=graphene.ID())
    vulnerabilities = graphene.List(lambda: Vulnerability, id=graphene.ID(), first=graphene.Int(), skip=graphene.Int(),
                                    last=graphene.Int())
    product_types = graphene.List(lambda: ProductType)
    commit = graphene.Field(lambda: Commit, id=graphene.ID())
    repository = graphene.Field(lambda: Repository, id=graphene.ID())
    repositories = graphene.List(Repository)
    product = graphene.Field(Product, id=graphene.ID())
    dataset = graphene.Field(lambda: Dataset, id=graphene.ID())
    datasets = graphene.List(lambda: Dataset)
    functions = graphene.List(lambda: MethodBoundary, file_id=graphene.String())
    profiles = graphene.List(lambda: ProfileCount)
    stats = graphene.Field(Stats)
    links = graphene.List(Link)


    def resolve_cwes(self, info, id=None, exists: bool = False):
        query = CWE.get_query(info)

        if id:
            query = query.filter(CWEModel.id == id)

        if exists:
            # return CWEs that have vulnerabilities associated
            query = query.join(VulnerabilityCWEModel)

        return query.order_by('id').all()

    def resolve_vulnerability(self, info, id: int):
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id == id).first()

    def resolve_vulnerabilities(self, info, id=None, first: int = None, skip: int = None, last: int = None, **kwargs):
        query = Vulnerability.get_query(info).order_by(VulnerabilityModel.published_date.desc())

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

    def resolve_stats(self, info):
        total = Vulnerability.get_query(info).count()
        references = Reference.get_query(info).count()
        labeled = VulnerabilityCWE.get_query(info).count()
        commits = Commit.get_query(info).count()

        return Stats(total, labeled, references, commits)

    def resolve_links(self, info):
        cwe_ids = CWE.get_query(info).all()
        mapping = {}

        for cwe in cwe_ids:
            cwe_counts = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.cwe_id == cwe.id).count()

            if cwe_counts < 1:
                continue

            bf_classes = CWE.resolve_bf_class(cwe, info)
            phases = CWE.resolve_phases(cwe, info)
            operations = CWE.resolve_operations(cwe, info)

            if len(bf_classes) > 1:
                continue

            if bf_classes[0].name == "None":
                continue

            if len(phases) > 1:
                continue

            link_name = f"{bf_classes[0].name}_{phases[0].name}"

            if link_name not in mapping:
                mapping[link_name] = Link(bf_classes[0].name, phases[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

            if len(operations) > 1:
                continue

            link_name = f"{phases[0].name}_{operations[0].name}"

            if link_name not in mapping:
                mapping[link_name] = Link(phases[0].name, operations[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

        return list(mapping.values())
