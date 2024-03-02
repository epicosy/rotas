import graphene

from sqlalchemy import or_
from typing import List
from graphene.types.objecttype import ObjectType


from arepo.models.common.vulnerability import VulnerabilityCWEModel, VulnerabilityModel
from arepo.models.common.weakness import CWEModel
from arepo.models.git import RepositoryModel


from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability
from rotas.objects.sqlalchemy.git import Repository, CommitFile, Commit
from rotas.objects.sqlalchemy.common.platform import Configuration, Vendor, Product


class Pagination(ObjectType):
    hasNextPage = graphene.Boolean()
    hasPreviousPage = graphene.Boolean()
    startCursor = graphene.Int()
    endCursor = graphene.Int()
    totalPages = graphene.Int()
    totalResults = graphene.Int()
    page = graphene.Int()
    perPage = graphene.Int()
    pages = graphene.List(graphene.Int)

    @classmethod
    def get_paginated(cls, query, page: int = 1, per_page: int = 10, left_edge: int = 4, right_edge: int = 4,
                      left_current: int = 5, right_current: int = 5):
        """
        Get a paginated response for a GraphQL query.

        Args:
            query: The query object to paginate.
            page (int, optional): The current page number.
            per_page (int, optional): The number of items per page.
            left_edge (int, optional): The number of pages displayed at the left edge.
            right_edge (int, optional): The number of pages displayed at the right edge.
            left_current (int, optional): The number of pages displayed to the left of the current page.
            right_current (int, optional): The number of pages displayed to the right of the current page.

        Returns:
            A paginated response object with the following fields:
            - hasNextPage: True if there is a next page, False otherwise.
            - hasPreviousPage: True if there is a previous page, False otherwise.
            - totalPages: The total number of pages.
            - totalResults: The total number of results.
            - page: The current page number.
            - perPage: The number of items per page.
            - pages: A list of page numbers.
            - elements: A list of paginated items.

        """

        paginated = query.paginate(page=page, per_page=per_page)
        pages = list(paginated.iter_pages(left_edge=left_edge, right_edge=right_edge, left_current=left_current,
                                          right_current=right_current))
        items = [item for item in paginated.items]

        # TODO: check if this is needed
        # startCursor=edges[0].cursor if edges else None,
        # endCursor=edges[-1].cursor if edges else None,
        return cls(hasNextPage=paginated.has_next, hasPreviousPage=paginated.has_prev,
                   totalPages=paginated.pages, totalResults=paginated.total, page=paginated.page,
                   perPage=paginated.per_page, pages=pages, elements=items)


class VulnerabilitiesPage(Pagination):
    elements = graphene.List(Vulnerability)


class CommitsPage(Pagination):
    elements = graphene.List(Commit)


class RepositoriesPage(Pagination):
    elements = graphene.List(Repository)


class ConfigurationsPage(Pagination):
    elements = graphene.List(Configuration)


class VendorsPage(Pagination):
    elements = graphene.List(Vendor)


class ProductsPage(Pagination):
    elements = graphene.List(Product)


class CommitFilesPage(Pagination):
    elements = graphene.List(CommitFile)


class PaginationQuery(ObjectType):
    vulnerabilities_page = graphene.Field(lambda: VulnerabilitiesPage, page=graphene.Int(), per_page=graphene.Int(),
                                          cwe_ids=graphene.List(graphene.Int), severity=graphene.List(graphene.String))
    commits_page = graphene.Field(lambda: CommitsPage, page=graphene.Int(), per_page=graphene.Int())
    repositories_page = graphene.Field(lambda: RepositoriesPage, page=graphene.Int(), per_page=graphene.Int(),
                                       availability=graphene.List(graphene.Boolean),
                                       language=graphene.List(graphene.String))
    configurations_page = graphene.Field(lambda: ConfigurationsPage, page=graphene.Int(), per_page=graphene.Int())
    vendors_page = graphene.Field(lambda: VendorsPage, page=graphene.Int(), per_page=graphene.Int())
    products_page = graphene.Field(lambda: ProductsPage, page=graphene.Int(), per_page=graphene.Int())
    commit_files_page = graphene.Field(lambda: CommitFilesPage, page=graphene.Int(), per_page=graphene.Int())

    def resolve_vulnerabilities_page(self, info, page=1, per_page=10, cwe_ids: List[int] = None,
                                     severity: List[str] = None):
        query = Vulnerability.get_query(info).order_by('published_date')

        if cwe_ids:
            query = query.join(VulnerabilityCWEModel).join(CWEModel)
            # TODO: check if the cwe-ids exist in the database
            query = query.filter(CWEModel.id.in_(cwe_ids))
            query = query.filter(VulnerabilityCWEModel.vulnerability_id == VulnerabilityModel.id)

        if severity:
            query = query.filter(VulnerabilityModel.severity.in_(severity))

        return VulnerabilitiesPage.get_paginated(query, page=page, per_page=per_page)

    def resolve_commits_page(self, info, page=1, per_page=10):
        query = Commit.get_query(info)

        return CommitsPage.get_paginated(query, page=page, per_page=per_page)

    def resolve_repositories_page(self, info, page=1, per_page=10, availability: List[bool] = None,
                                  language: List[str] = None):
        query = Repository.get_query(info).order_by()

        if availability:
            query = query.filter(or_(RepositoryModel.available.in_(availability), RepositoryModel.available.is_(None)))

        if language:
            query = query.filter(RepositoryModel.language.in_(language))

        return RepositoriesPage.get_paginated(query, page=page, per_page=per_page)

    def resolve_configurations_page(self, info, page=1, per_page=10):
        query = Configuration.get_query(info)

        return ConfigurationsPage.get_paginated(query, page=page, per_page=per_page)

    def resolve_vendors_page(self, info, page=1, per_page=10):
        query = Vendor.get_query(info)

        return VendorsPage.get_paginated(query, page=page, per_page=per_page)

    def resolve_products_page(self, info, page=1, per_page=10):
        query = Product.get_query(info)

        return ProductsPage.get_paginated(query, page=page, per_page=per_page)

    def resolve_commit_files_page(self, info, page=1, per_page=10):
        query = CommitFile.get_query(info)

        return CommitFilesPage.get_paginated(query, page=page, per_page=per_page)
