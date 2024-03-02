import graphene

from graphql import GraphQLError


from arepo.models.git import RepositoryProductTypeModel
from rotas.objects.sqlalchemy.git import Repository, ProductType, RepositoryProductType


class EditRepositorySoftwareType(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)
        software_type_id = graphene.Int(required=True)

    repository = graphene.Field(lambda: Repository)

    def mutate(self, info, id: str, software_type_id: int):
        repository = Repository.get_query(info).filter_by(id=id).first()

        if not repository:
            raise GraphQLError(f"Repository with id {id} does not exist")

        software_type = ProductType.get_query(info).filter_by(id=software_type_id).first()

        if not software_type:
            raise GraphQLError(f"Software type with id {software_type_id} does not exist")

        repository_product_type = RepositoryProductType.get_query(info).filter_by(repository_id=id).first()

        if repository_product_type:
            repository_product_type.product_type_id = software_type_id
        else:
            repository_product_type = RepositoryProductTypeModel(repository_id=id, product_type_id=software_type_id)

        repository_product_type.save()
        repository.software_type = software_type.name

        return EditRepositorySoftwareType(repository=repository)
