import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType
from arepo.models.common.platform import (ProductTypeModel, ProductModel, VendorModel, ConfigurationModel,
                                          ConfigurationVulnerabilityModel)


class ProductType(SQLAlchemyObjectType):
    class Meta:
        model = ProductTypeModel
        use_connection = True


class Product(SQLAlchemyObjectType):
    class Meta:
        model = ProductModel
        use_connection = True

    product_type_id = graphene.Int()
    sw_type = graphene.String()
    configurations = graphene.List(lambda: Configuration)
    configurations_count = graphene.Int()
    vulnerabilities_count = graphene.Int()

    def resolve_product_type_id(self, info):
        return self.product_type_id

    def resolve_sw_type(self, info):
        return ProductType.get_query(info).filter(self.product_type_id == ProductTypeModel.id).first().name

    def resolve_configurations(self, info):
        return self.configurations

    def resolve_configurations_count(self, info):
        return len(self.configurations)

    def resolve_vulnerabilities_count(self, info):
        return len(set([config.vulnerability_id for config in self.configurations]))


class Vendor(SQLAlchemyObjectType):
    class Meta:
        model = VendorModel
        use_connection = True

    products = graphene.List(lambda: Product)
    products_count = graphene.Int()
    configurations = graphene.List(lambda: Configuration)
    configurations_count = graphene.Int()
    vulnerabilities_count = graphene.Int()

    def resolve_products_count(self, info):
        return len(self.products)

    def resolve_configurations(self, info):
        return [config for product in self.products for config in product.configurations]

    def resolve_configurations_count(self, info):
        return len([config for product in self.products for config in product.configurations])

    def resolve_vulnerabilities_count(self, info):
        return len(set([config.vulnerability_id for product in self.products for config in product.configurations]))


class Configuration(SQLAlchemyObjectType):
    class Meta:
        model = ConfigurationModel
        use_connection = True


class ConfigurationVulnerability(SQLAlchemyObjectType):
    class Meta:
        model = ConfigurationVulnerabilityModel
        use_connection = True
