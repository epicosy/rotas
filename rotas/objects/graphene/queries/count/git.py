import graphene
import sqlalchemy

from typing import List
from graphql import GraphQLError
from graphene import ObjectType
from sqlalchemy.sql import func
from sqlalchemy.sql import select

from arepo.models.common.platform import ProductTypeModel, ConfigurationModel, ProductModel
from arepo.models.common.vulnerability import VulnerabilityModel, VulnerabilityCWEModel
from arepo.models.git import CommitModel, RepositoryModel, CommitFileModel, RepositoryTopicModel, TopicModel

from rotas.objects.sqlalchemy.common.vulnerability import VulnerabilityCWE
from rotas.objects.sqlalchemy.common.platform import ProductType
from rotas.objects.sqlalchemy.git import (Commit, Repository, CommitFile, RepositoryProductType,
                                          RepositoryProductTypeModel)

from rotas.objects.graphene.helpers.types import GrapheneCount, LinkCount, ProfileCount
from rotas.objects.graphene.helpers.query import profiling_vuln_query, profiling_commit_query


class GitCountQuery(ObjectType):
    topics_count = graphene.List(lambda: GrapheneCount)
    language_extension_links_count = graphene.List(lambda: LinkCount, filter_counts=graphene.Int())
    lang_product_links_count = graphene.List(lambda: LinkCount, filter_counts=graphene.Int())
    sw_type_vulnerability_profile = graphene.List(lambda: GrapheneCount, sw_type=graphene.String(),
                                                  repo_id=graphene.String())

    commit_kind_count = graphene.List(lambda: GrapheneCount)
    commits_availability = graphene.List(lambda: GrapheneCount)
    commits_state = graphene.List(lambda: GrapheneCount)
    commits_files_count = graphene.List(lambda: GrapheneCount)
    commits_changes_count = graphene.List(lambda: GrapheneCount)

    repositories_commits_frequency = graphene.List(lambda: GrapheneCount)
    repositories_availability = graphene.List(lambda: GrapheneCount)
    repositories_language_count = graphene.List(lambda: GrapheneCount)
    repositories_software_type_count = graphene.List(lambda: GrapheneCount)

    files_extensions = graphene.List(lambda: GrapheneCount)
    files_changes_count = graphene.List(lambda: GrapheneCount)
    files_statuses = graphene.List(lambda: GrapheneCount)

    profile_count = graphene.Field(ProfileCount, start_year=graphene.Int(), end_year=graphene.Int(),
                                   cwe_ids=graphene.List(graphene.Int), start_score=graphene.Float(),
                                   end_score=graphene.Float(), has_code=graphene.Boolean(), has_exploit=graphene.Boolean(),
                                   has_advisory=graphene.Boolean(), min_changes=graphene.Int(),
                                   max_changes=graphene.Int(), min_files=graphene.Int(), max_files=graphene.Int(),
                                   extensions=graphene.List(graphene.String))

    def resolve_topics_count(self, info):
        query = Repository.get_query(info).join(RepositoryTopicModel).join(TopicModel)\
            .group_by(TopicModel.name).with_entities(TopicModel.name, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_language_extension_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(CommitFileModel)\
            .group_by(RepositoryModel.language, CommitFileModel.extension)\
            .with_entities(RepositoryModel.language, CommitFileModel.extension, sqlalchemy.func.count()).all()

        if filter_counts:
            return [LinkCount(at=at, to=to, count=count) for at, to, count in query if count >= filter_counts]

        return [LinkCount(at=at, to=to, count=count) for at, to, count in query]

    # TODO: this kind of resolver combines many different models, it should be refactored
    def resolve_lang_product_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(VulnerabilityModel).join(ConfigurationModel)\
            .join(ProductModel).join(ProductTypeModel).filter(RepositoryModel.language != None)\
            .group_by(RepositoryModel.language, ProductTypeModel.name)\
            .with_entities(RepositoryModel.language, ProductTypeModel.name, sqlalchemy.func.count()).all()

        if filter_counts:
            return [LinkCount(at=at, to=to, count=count) for at, to, count in query if count > filter_counts]

        return [LinkCount(at=at, to=to, count=count) for at, to, count in query]

    # TODO: this kind of resolver combines many different models, it should be refactored
    def resolve_sw_type_vulnerability_profile(self, info, sw_type: str, repo_id: str = None):
        sw_type = ProductType.get_query(info).filter(ProductTypeModel.name == sw_type).first()

        if not sw_type:
            raise GraphQLError(f"Software type {sw_type} not found")

        # TODO: refactor this to be done in the query
        repos_ids = RepositoryProductType.get_query(info).filter(
            RepositoryProductTypeModel.product_type_id == sw_type.id).all()
        to_exclude = None

        if repo_id:
            repo = Repository.get_query(info).filter(RepositoryModel.id == repo_id).first()

            if repo:
                to_exclude = repo.id

        repos = Repository.get_query(info).filter(
            RepositoryModel.id.in_([r.repository_id for r in repos_ids if r.repository_id != to_exclude])).all()

        commits = [c for r in repos for c in r.commits]
        vulns = [c.vulnerability_id for c in commits]
        cwes = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.vulnerability_id.in_(vulns)). \
            group_by(VulnerabilityCWEModel.cwe_id). \
            with_entities(VulnerabilityCWEModel.cwe_id, sqlalchemy.func.count(VulnerabilityCWEModel.cwe_id)).all()

        return [GrapheneCount(key=cwe, value=count) for cwe, count in cwes]

    def resolve_commit_kind_count(self, info):
        # the following counts the number of commits of each kind by the kind field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.kind).with_entities(CommitModel.kind, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_commits_availability(self, info):
        # the following counts the number of commits of each availability by the availability field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.available).with_entities(CommitModel.available,
                                                                     sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'awaiting', value=v) for k, v in counts]

    def resolve_commits_state(self, info):
        # the following counts the number of commits of each state by the state field
        query = Commit.get_query(info)
        counts = query.group_by(CommitModel.state).with_entities(CommitModel.state,
                                                                 sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'awaiting', value=v) for k, v in counts]


    def resolve_commits_files_count(self, info):
        query = Commit.get_query(info).group_by(CommitModel.files_count).\
            with_entities(CommitModel.files_count, sqlalchemy.func.count(CommitModel.files_count))\
            .order_by(CommitModel.files_count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_commits_changes_count(self, info):
        query = Commit.get_query(info).group_by(CommitModel.changes).\
            with_entities(CommitModel.changes, sqlalchemy.func.count(CommitModel.changes))\
            .order_by(CommitModel.changes).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_repositories_commits_frequency(self, info):
        subquery = Commit.get_query(info).filter(CommitModel.kind != 'parent').group_by(CommitModel.repository_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Commit.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count))\
            .group_by(subquery.c.count). order_by(subquery.c.count)

        count_of_counts = query.all()

        return [GrapheneCount(key=k, value=v) for k, v in count_of_counts]

    def resolve_repositories_availability(self, info):
        # the following counts the number of repositories of each availability by the availability field
        query = Repository.get_query(info)
        counts = query.group_by(RepositoryModel.available).with_entities(RepositoryModel.available,
                                                                         sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'awaiting', value=v) for k, v in counts]

    def resolve_repositories_language_count(self, info):
        # the following counts the number of repositories of each language by the language field
        query = Repository.get_query(info)
        counts = query.group_by(RepositoryModel.language).with_entities(RepositoryModel.language,
                                                                        sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_repositories_software_type_count(self, info):
        count = RepositoryProductType.get_query(info).join(ProductTypeModel).group_by(ProductTypeModel.name).\
            with_entities(ProductTypeModel.name, sqlalchemy.func.count(ProductTypeModel.name)).all()

        return [GrapheneCount(key=k, value=v) for k, v in count]

    def resolve_files_extensions(self, info):
        query = CommitFile.get_query(info).group_by(CommitFileModel.extension).\
            with_entities(CommitFileModel.extension, sqlalchemy.func.count(CommitFileModel.extension))\
            .order_by(CommitFileModel.extension).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_files_changes_count(self, info):
        query = CommitFile.get_query(info).group_by(CommitFileModel.changes).\
            with_entities(CommitFileModel.changes, sqlalchemy.func.count(CommitFileModel.changes))\
            .order_by(CommitFileModel.changes).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_files_statuses(self, info):
        query = CommitFile.get_query(info).group_by(CommitFileModel.status).\
            with_entities(CommitFileModel.status, sqlalchemy.func.count(CommitFileModel.status)).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_profile_count(self, info, start_year: int = None, end_year: int = None, cwe_ids: List[int] = None,
                              start_score: float = None, end_score: float = None, has_code: bool = False,
                              has_exploit: bool = False, has_advisory: bool = False, min_changes: int = None,
                              max_changes: int = None, min_files: int = None, max_files: int = None,
                              extensions: List[str] = None):

        changes_count = []
        files_count = []
        extensions_count = []

        print("has_code", has_code, "min_changes", min_changes, "max_changes", max_changes)

        query = profiling_vuln_query(info, start_year, end_year, cwe_ids, start_score, end_score, has_exploit,
                                     has_advisory)

        if has_code:
            commit_query = profiling_commit_query(info, query, min_changes, max_changes, min_files, max_files,
                                                  extensions)

            vuln_query = commit_query.with_entities(CommitModel.vulnerability_id).subquery()
            query = query.filter(VulnerabilityModel.id.in_(select([vuln_query])))

            changes_count = (commit_query.group_by(CommitModel.changes)
                             .with_entities(CommitModel.changes, func.count().label('count'))
                             .all())

            files_count = (commit_query.group_by(CommitModel.files_count)
                           .with_entities(CommitModel.files_count, func.count().label('count'))
                           .all())

            commit_subquery = commit_query.with_entities(CommitModel.id).subquery()
            extensions_count = (
                CommitFile.get_query(info).filter(CommitFileModel.commit_id.in_(select([commit_subquery])))
                .group_by(CommitFileModel.extension)
                .with_entities(CommitFileModel.extension, func.count().label('count'))
                .all())

        year_counts = query.group_by(
            func.extract('year', VulnerabilityModel.published_date)
        ).with_entities(
            func.extract('year', VulnerabilityModel.published_date).label('year'),
            func.count().label('count')
        ).all()

        cwe_counts = query.group_by(
            VulnerabilityCWEModel.cwe_id
        ).with_entities(
            VulnerabilityCWEModel.cwe_id,
            func.count().label('count')
        ).all()

        score_counts = query.group_by(
            VulnerabilityModel.exploitability
        ).with_entities(
            VulnerabilityModel.exploitability.label('score'),
            func.count().label('count')
        ).all()

        return ProfileCount(year=[GrapheneCount(key=year, value=count) for year, count in year_counts],
                            cwe=[GrapheneCount(key=cwe_id, value=count) for cwe_id, count in cwe_counts],
                            score=[GrapheneCount(key=score, value=count) for score, count in score_counts],
                            changes=[GrapheneCount(key=changes, value=count) for changes, count in changes_count],
                            files=[GrapheneCount(key=files, value=count) for files, count in files_count],
                            extensions=[GrapheneCount(key=extension, value=count) for extension, count in extensions_count],
                            total=query.count())
