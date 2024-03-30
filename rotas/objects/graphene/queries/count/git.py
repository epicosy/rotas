import graphene
import sqlalchemy

from typing import List
from graphql import GraphQLError
from graphene import ObjectType

from arepo.models.common.platform import ProductTypeModel, ConfigurationModel, ProductModel
from arepo.models.common.vulnerability import VulnerabilityModel, VulnerabilityCWEModel
from arepo.models.vcs.core import CommitModel, RepositoryModel, CommitFileModel
from arepo.models.vcs.symbol import RepositoryTopicModel, TopicModel

from rotas.objects.sqlalchemy.common.vulnerability import VulnerabilityCWE
from rotas.objects.sqlalchemy.common.platform import ProductType
from rotas.objects.sqlalchemy.git import (Commit, Repository, CommitFile, RepositoryProductType,
                                          RepositoryProductTypeModel)

from rotas.objects.graphene.helpers.types import GrapheneCount, LinkCount, ProfileCount
from rotas.objects.graphene.helpers.query import ProfilerQuery


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

    profile_count = graphene.Field(ProfileCount, bf_class=graphene.String(), cwe_ids=graphene.List(graphene.Int),
                                   language=graphene.String(), has_exploit=graphene.Boolean(),
                                   has_advisory=graphene.Boolean(), patch_count=graphene.Int(),
                                   min_changes=graphene.Int(), max_changes=graphene.Int(), min_files=graphene.Int(),
                                   max_files=graphene.Int(), extensions=graphene.List(graphene.String))

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

    def resolve_profile_count(self, info, cwe_ids: List[int] = None, bf_class: str = None, language: str = None,
                              has_exploit: bool = False, has_advisory: bool = False, patch_count: int = None,
                              min_changes: int = None,  max_changes: int = None, min_files: int = None,
                              max_files: int = None, extensions: List[str] = None, diff_block_count: int = None):

        profiler_query = ProfilerQuery(info)

        profiler_query.profile_vulnerability(bf_class, cwe_ids, has_exploit, has_advisory)
        profiler_query.profile_commit_file(extensions, diff_block_count)
        profiler_query.profile_commit(language, patch_count, min_changes, max_changes, min_files, max_files)
        profiler_query()

        return ProfileCount(classes=[GrapheneCount(key, count) for key, count in profiler_query.get_bf_class_counts()],
                            cwe=[GrapheneCount(key, count) for key, count in profiler_query.get_cwe_counts()],
                            patches=[GrapheneCount(key, count) for key, count in profiler_query.get_patch_counts()],
                            languages=[GrapheneCount(key, count) for key, count in profiler_query.get_language_counts()],
                            changes=[GrapheneCount(key, count) for key, count in profiler_query.get_changes_counts()],
                            files=[GrapheneCount(key, count) for key, count in profiler_query.get_files_counts()],
                            extensions=[GrapheneCount(key, count) for key, count in profiler_query.get_extension_counts()],
                            diff_blocks=[GrapheneCount(key, count) for key, count in profiler_query.get_diff_block_counts()],
                            total=profiler_query.get_total())
