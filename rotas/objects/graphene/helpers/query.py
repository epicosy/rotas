import sqlalchemy

from graphql import GraphQLError
from sqlalchemy.sql import select

from rotas.objects.sqlalchemy.common.vulnerability import (Vulnerability, VulnerabilityModel, Reference, ReferenceModel,
                                                           VulnerabilityCWEModel, ReferenceTagModel)
from rotas.objects.sqlalchemy.git import Commit, CommitModel, CommitFile, CommitFileModel


def check_profile_vuln_fields(start_year, end_year, start_score, end_score):
    # min score should not be negative and max score should not be greater than 100
    if start_score and start_score < 0:
        raise GraphQLError("Invalid min score")

    if end_score and end_score > 10:
        raise GraphQLError("Invalid max score")

    if start_year and start_year < 1987:
        raise GraphQLError("Invalid start year")

    if end_year:
        from datetime import datetime

        # should not be greater than the current year by 1, get year with Date
        if end_year > datetime.now().year + 1:
            raise GraphQLError("Invalid end year")

    if start_year and end_year and start_year > end_year:
        raise GraphQLError("Invalid date range")

    if start_score and end_score and start_score > end_score:
        raise GraphQLError("Invalid score range")


def check_profile_commit_fields(min_changes, max_changes, min_files, max_files):
    if min_changes and min_changes < 0:
        raise GraphQLError("Invalid min changes")

    if min_files and min_files < 0:
        raise GraphQLError("Invalid min files")

    if min_changes and max_changes and min_changes > max_changes:
        raise GraphQLError("Invalid files range")

    if min_files and max_files and min_files > max_files:
        raise GraphQLError("Invalid changes range")


def profiling_vuln_query(info, start_year, end_year, cwe_ids, start_score, end_score, has_exploit, has_advisory):
    check_profile_vuln_fields(start_year, end_year, start_score, end_score)

    query = Vulnerability.get_query(info).outerjoin(VulnerabilityCWEModel,
                                                    VulnerabilityModel.id == VulnerabilityCWEModel.vulnerability_id)

    if cwe_ids:
        query = query.filter(VulnerabilityCWEModel.cwe_id.in_(cwe_ids))

    if start_year:
        query = query.filter(VulnerabilityModel.published_date >= f'{start_year}-01-01')

    if end_year:
        query = query.filter(VulnerabilityModel.published_date <= f'{end_year}-12-31')

    if start_score:
        query = query.filter(VulnerabilityModel.exploitability >= start_score)

    if end_score:
        query = query.filter(VulnerabilityModel.exploitability <= end_score)

    if has_exploit:
        # get the ReferenceTag id for the exploit tag
        subquery = Reference.get_query(info).join(ReferenceTagModel).filter(ReferenceTagModel.tag_id == 10). \
            distinct().filter(ReferenceModel.vulnerability_id == VulnerabilityModel.id).exists()

        query = query.filter(subquery)

    if has_advisory:
        # get the ReferenceTag id for the advisory tag (1 and 16)
        subquery = Reference.get_query(info).join(ReferenceTagModel).filter(ReferenceTagModel.tag_id.in_([1, 16])). \
            distinct().filter(ReferenceModel.vulnerability_id == VulnerabilityModel.id).exists()

        query = query.filter(subquery)

    return query


def profiling_commit_query(info, query, min_changes, max_changes, min_files, max_files, extensions):
    check_profile_commit_fields(min_changes, max_changes, min_files, max_files)

    vuln_query = query.with_entities(VulnerabilityModel.id).subquery()
    commit_query = (Commit.get_query(info).filter(sqlalchemy.exists().where(CommitModel.vulnerability_id == vuln_query.c.id))
                    .filter(CommitModel.kind != 'parent'))

    commit_query = commit_query.filter(CommitModel.changes.isnot(None))
    commit_query = commit_query.filter(CommitModel.files_count.isnot(None))

    if min_changes or max_changes or min_files or max_files:
        commit_query = commit_query.group_by(CommitModel.id, CommitModel.vulnerability_id)

        if min_changes or max_changes:
            if min_changes:
                commit_query = commit_query.having(sqlalchemy.func.min(CommitModel.changes) >= min_changes)

            if max_changes:
                commit_query = commit_query.having(sqlalchemy.func.max(CommitModel.changes) <= max_changes)

        if min_files or max_files:
            if min_files:
                commit_query = commit_query.having(sqlalchemy.func.min(CommitModel.files_count) >= min_files)

            if max_files:
                commit_query = commit_query.having(sqlalchemy.func.max(CommitModel.files_count) <= max_files)

        subquery = commit_query.subquery()
        commit_query = (Commit.get_query(info).join(subquery, CommitModel.id == subquery.c.id)
                        .filter(subquery.c.vulnerability_id == CommitModel.vulnerability_id))

    if extensions:
        extension_subquery = (CommitFile.get_query(info)
                              .filter(CommitFileModel.commit_id == CommitModel.id)
                              .filter(CommitFileModel.extension.in_(extensions))
                              .subquery())

        commit_query = commit_query.join(extension_subquery, extension_subquery.c.commit_id == CommitModel.id)

    return commit_query
