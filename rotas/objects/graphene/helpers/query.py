import sqlalchemy

from typing import List
from graphql import GraphQLError

from rotas.objects.sqlalchemy.common.vulnerability import (Vulnerability, VulnerabilityModel, Reference, ReferenceModel,
                                                           VulnerabilityCWE, VulnerabilityCWEModel, ReferenceTagModel)
from rotas.objects.sqlalchemy.common.weakness import CWEBFClassModel
from rotas.objects.sqlalchemy.bf import BFClassModel
from rotas.objects.sqlalchemy.git import Commit, CommitModel, CommitFile, CommitFileModel, RepositoryModel, Repository
from rotas.objects.sqlalchemy.git import DiffBlock, DiffBlockModel


def check_profile_vuln_fields(start_year, end_year):
    # min score should not be negative and max score should not be greater than 100

    # if start_score and start_score < 0:
    #    raise GraphQLError("Invalid min score")

    # if end_score and end_score > 10:
    #    raise GraphQLError("Invalid max score")

    if start_year and start_year < 1987:
        raise GraphQLError("Invalid start year")

    if end_year:
        from datetime import datetime

        # should not be greater than the current year by 1, get year with Date
        if end_year > datetime.now().year + 1:
            raise GraphQLError("Invalid end year")

    if start_year and end_year and start_year > end_year:
        raise GraphQLError("Invalid date range")

    # if start_score and end_score and start_score > end_score:
    #    raise GraphQLError("Invalid score range")


def check_profile_commit_fields(min_changes, max_changes, min_files, max_files):
    if min_changes and min_changes < 0:
        raise GraphQLError("Invalid min changes")

    if min_files and min_files < 0:
        raise GraphQLError("Invalid min files")

    if min_changes and max_changes and min_changes > max_changes:
        raise GraphQLError("Invalid files range")

    if min_files and max_files and min_files > max_files:
        raise GraphQLError("Invalid changes range")


class ProfilerQuery:
    def __init__(self, info):
        self.info = info
        self._query = None
        self.vuln_cwe_query = VulnerabilityCWE.get_query(self.info)
        self.diff_block_query = DiffBlock.get_query(self.info)
        self.commit_file_query = CommitFile.get_query(self.info)
        self.commit_query = (Commit.get_query(self.info).filter(CommitModel.kind != 'parent')
                             .filter(CommitModel.changes.isnot(None)).filter(CommitModel.files_count.isnot(None)))
        self.repo_query = Repository.get_query(self.info)
        self.vuln_query = (Vulnerability.get_query(self.info)
                           .outerjoin(VulnerabilityCWEModel, VulnerabilityModel.id == VulnerabilityCWEModel.vulnerability_id)
                           .outerjoin(CWEBFClassModel, CWEBFClassModel.cwe_id == VulnerabilityCWEModel.cwe_id)
                           .outerjoin(BFClassModel, BFClassModel.id == CWEBFClassModel.bf_class_id))

        self.reference_query = Reference.get_query(self.info)

    def profile_commit_file(self, extensions: List[str] = None, diff_block_count: int = None):
        if extensions:
            print(f"Filtering by extensions: {extensions}")
            self.commit_file_query = self.commit_file_query.filter(CommitFileModel.extension.in_(extensions))

        if diff_block_count and diff_block_count > 0:
            print(f"Filtering by diff_block_count: {diff_block_count}")
            subquery = (self.diff_block_query.group_by(DiffBlockModel.commit_file_id)
                        .having(sqlalchemy.func.count(DiffBlockModel.commit_file_id) == diff_block_count)
                        .with_entities(DiffBlockModel.commit_file_id).subquery())

            self.commit_file_query = self.commit_file_query.filter(CommitFileModel.id == subquery.c.commit_file_id)

    def profile_commit(self, repo_lang: str = None, patch_count: int = None, min_changes: int = None,
                       max_changes: int = None, min_files: int = None, max_files: int = None):

        check_profile_commit_fields(min_changes, max_changes, min_files, max_files)

        if patch_count and patch_count > 0:
            print(f"Filtering by patch count: {patch_count}")
            # Get distinct vuln_ids that have only commit count
            commit_count_subquery = (self.commit_query.group_by(CommitModel.vulnerability_id)
                                     .having(sqlalchemy.func.count(CommitModel.vulnerability_id) == patch_count)
                                     .with_entities(CommitModel.vulnerability_id).subquery())

            # Filter the main commit_query by the distinct commit_ids
            self.commit_query = self.commit_query.filter(
                CommitModel.vulnerability_id == commit_count_subquery.c.vulnerability_id)

        if repo_lang:
            print(f"Filtering by repo_lang: {repo_lang}")
            # find the commit ids that have the repo_lang
            repo_lang_subquery = (self.repo_query.filter(RepositoryModel.language == repo_lang)
                                  .join(CommitModel.repository).with_entities(CommitModel.id).subquery())

            # filter the main commit_query by the commit ids
            self.commit_query = self.commit_query.filter(CommitModel.id == repo_lang_subquery.c.id)

        if min_changes or max_changes or min_files or max_files:
            changes_query = self.commit_query.group_by(CommitModel.id, CommitModel.vulnerability_id)

            if min_changes or max_changes:
                if min_changes:
                    print(f"Filtering by min_changes: {min_changes}")
                    changes_query = changes_query.having(sqlalchemy.func.min(CommitModel.changes) >= min_changes)

                if max_changes:
                    print(f"Filtering by max_changes: {max_changes}")
                    changes_query = changes_query.having(sqlalchemy.func.max(CommitModel.changes) <= max_changes)

            if min_files or max_files:
                if min_files:
                    print(f"Filtering by min_files: {min_files}")
                    changes_query = changes_query.having(sqlalchemy.func.min(CommitModel.files_count) >= min_files)

                if max_files:
                    print(f"Filtering by max_files: {max_files}")
                    changes_query = changes_query.having(sqlalchemy.func.max(CommitModel.files_count) <= max_files)

            subquery = changes_query.subquery()
            self.commit_query = self.commit_query.filter(CommitModel.id == subquery.c.id)

    def profile_vulnerability(self, bf_class: str = None, cwe_ids: List[int] = None, has_exploit: bool = None,
                              has_advisory: bool = None):

        # check_profile_vuln_fields(start_year, end_year)

        if bf_class:
            print(f"Filtering by bf_class: {bf_class}")
            self.vuln_query = self.vuln_query.filter(BFClassModel.name == bf_class)

        if cwe_ids:
            print(f"Filtering by cwe_ids: {cwe_ids}")
            self.vuln_query = self.vuln_query.filter(VulnerabilityCWEModel.cwe_id.in_(cwe_ids))

        # if start_year:
        #    print(f"Filtering by start_year: {start_year}")
        #    self.vuln_query = self.vuln_query.filter(VulnerabilityModel.published_date >= f'{start_year}-01-01')

        # if end_year:
        #    print(f"Filtering by end_year: {end_year}")
        #    self.vuln_query = self.vuln_query.filter(VulnerabilityModel.published_date <= f'{end_year}-12-31')

        if has_exploit:
            print("Including only vulnerabilities with exploits")
            # get the ReferenceTag id for the exploit tag
            subquery = self.reference_query.join(ReferenceTagModel).filter(ReferenceTagModel.tag_id == 10). \
                distinct().filter(ReferenceModel.vulnerability_id == VulnerabilityModel.id).exists()

            self.vuln_query = self.vuln_query.filter(subquery)

        if has_advisory:
            print("Including only vulnerabilities with advisories")
            # get the ReferenceTag id for the advisory tag (1 and 16)
            subquery = (self.reference_query.join(ReferenceTagModel)
                        .filter(ReferenceTagModel.tag_id.in_([1, 16]))
                        .distinct().filter(ReferenceModel.vulnerability_id == VulnerabilityModel.id).exists())

            self.vuln_query = self.vuln_query.filter(subquery)

    def __call__(self):
        if self._query is None:
            subquery = self.commit_file_query.with_entities(CommitFileModel.commit_id).distinct().subquery()
            self.commit_query = (self.commit_query
                                 .filter(sqlalchemy.exists().where(CommitFileModel.commit_id == subquery.c.commit_id)))

            subquery = self.commit_query.with_entities(CommitModel.vulnerability_id).distinct().subquery()
            self.vuln_query = (self.vuln_query
                               .filter(sqlalchemy.exists().where(VulnerabilityModel.id == subquery.c.vulnerability_id)))
            self._query = self.vuln_query.with_entities(VulnerabilityModel.id).distinct().subquery()

            # propagate the query to the subqueries
            self.commit_query = (self.commit_query
                                 .filter(sqlalchemy.exists().where(CommitModel.vulnerability_id == self._query.c.id)))
            subquery = self.commit_query.with_entities(CommitModel.id).subquery()
            # TODO: check why this does not propagate back the changes
            self.commit_file_query = (self.commit_file_query
                                      .filter(sqlalchemy.exists().where(CommitFileModel.commit_id == subquery.c.id)))

        return self._query

    def get_cwe_counts(self):
        return (self.vuln_query.group_by(VulnerabilityCWEModel.cwe_id)
                .with_entities(VulnerabilityCWEModel.cwe_id, sqlalchemy.func.count().label('count')).all())

    def get_bf_class_counts(self):
        # TODO: fix this to retrieve the number of vulnerabilities per bf_class for the vuln_query and not the entire db
        return (self.vuln_query.group_by(BFClassModel.name)
                .with_entities(BFClassModel.name, sqlalchemy.func.count().label('count')).all())

    def get_language_counts(self):
        subquery = (self.commit_query.group_by(CommitModel.repository_id, CommitModel.vulnerability_id)
                    .with_entities(CommitModel.repository_id).subquery())

        return (self.repo_query.filter(RepositoryModel.id == subquery.c.repository_id)
                .group_by(RepositoryModel.language)
                .with_entities(RepositoryModel.language, sqlalchemy.func.count().label('count')).all())

    def get_patch_counts(self):
        # TODO: optimize this, it is very slow
        subquery = (self.commit_query.group_by(CommitModel.vulnerability_id).
                    with_entities(sqlalchemy.func.count().label('count')).subquery())

        return (Vulnerability.get_query(self.info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).
                group_by(subquery.c.count).order_by(subquery.c.count).all())

    def get_changes_counts(self):
        return (self.commit_query.group_by(CommitModel.changes)
                .with_entities(CommitModel.changes, sqlalchemy.func.count().label('count')).all())

    def get_files_counts(self):
        return (self.commit_query.group_by(CommitModel.files_count)
                .with_entities(CommitModel.files_count, sqlalchemy.func.count().label('count')).all())

    def get_extension_counts(self):
        return (self.commit_file_query.group_by(CommitFileModel.extension)
                .with_entities(CommitFileModel.extension, sqlalchemy.func.count().label('count')).all())

    def get_diff_block_counts(self):
        subquery = (self.commit_file_query.join(CommitFileModel.diff_blocks).group_by(CommitFileModel.id)
                    .with_entities(CommitFileModel.id, sqlalchemy.func.count(DiffBlockModel.id).label('count')).subquery())

        return (CommitFile.get_query(self.info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count))
                .group_by(subquery.c.count).order_by(subquery.c.count).all())

    def get_total(self):
        return self.vuln_query.count()
