import graphene
import sqlalchemy

from graphene.types.objecttype import ObjectType


from arepo.models.common.vulnerability import VulnerabilityModel, VulnerabilityCWEModel, ReferenceTagModel, TagModel
from arepo.models.common.platform import (ConfigurationModel, ConfigurationVulnerabilityModel, VendorModel,
                                          ProductModel, ProductTypeModel)
from arepo.models.common.weakness import CWEModel, GroupingModel

from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability, Reference, Tag, VulnerabilityCWE
from rotas.objects.sqlalchemy.common.platform import Configuration, Product
from rotas.objects.sqlalchemy.common.weakness import CWE, Grouping
from rotas.objects.graphene.helpers.types import GrapheneCount, NestedGrapheneCount

from rotas.utils import extract_company


class CommonCountQuery(ObjectType):
    cwe_counts = graphene.List(lambda: GrapheneCount)
    cwe_multiplicity = graphene.List(lambda: GrapheneCount)
    tags_count = graphene.List(lambda: GrapheneCount)
    assigners_count = graphene.List(lambda: GrapheneCount, company=graphene.Boolean())
    sw_type_count = graphene.List(lambda: GrapheneCount)
    products_count_by_vendor = graphene.List(lambda: GrapheneCount)

    vulns_by_year = graphene.List(GrapheneCount)
    vulns_severity = graphene.List(lambda: GrapheneCount)
    vulns_exploitability = graphene.List(lambda: GrapheneCount)
    vulns_count_by_vendor = graphene.List(lambda: GrapheneCount)
    vulns_count_by_product = graphene.List(lambda: GrapheneCount)
    vulns_count_by_sof_dev_view = graphene.List(lambda: GrapheneCount)

    configs_part_count = graphene.List(lambda: NestedGrapheneCount)
    configs_vulns_count = graphene.List(lambda: GrapheneCount)
    configs_count_by_vendor = graphene.List(lambda: GrapheneCount)
    configs_count_by_product = graphene.List(lambda: GrapheneCount)

    def resolve_tags_count(self, info):
        query = Reference.get_query(info).join(ReferenceTagModel).join(TagModel)
        counts = {}

        for tag in Tag.get_query(info).all():
            tag_counts = query.filter(TagModel.name == tag.name).count()

            if tag not in counts:
                counts[tag.name] = tag_counts
            else:
                counts[tag.name] += tag_counts

        return [GrapheneCount(key=k, value=v) for k, v in counts.items()]

    def resolve_cwe_counts(self, info):
        cwe_counts = Vulnerability.get_query(info).join(VulnerabilityCWEModel).join(CWEModel).group_by(CWEModel.id).\
            with_entities(CWEModel.id, sqlalchemy.func.count()).order_by(CWEModel.id).all()

        return [GrapheneCount(key=k, value=v) for k, v in cwe_counts]

    @staticmethod
    def resolve_assigners_count(parent, info, company: bool = False):
        # TODO: this resolver is slow and needs to be optimized
        assigners = Vulnerability.get_query(info).distinct(VulnerabilityModel.assigner)
        counts = {}

        for vuln in assigners:
            assigner_counts = Vulnerability.get_query(info).filter(VulnerabilityModel.assigner == vuln.assigner).count()

            assigner = extract_company(vuln.assigner) if company else vuln.assigner

            if assigner not in counts:
                counts[assigner] = assigner_counts
            else:
                counts[assigner] += assigner_counts

        return [GrapheneCount(key=k, value=v) for k, v in counts.items()]

    def resolve_sw_type_count(self, info):
        query = Product.get_query(info).join(ProductTypeModel)
        counts = query.group_by(ProductTypeModel.name).with_entities(ProductTypeModel.name, sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_cwe_multiplicity(self, info):
        subquery = VulnerabilityCWE.get_query(info).join(VulnerabilityModel).group_by(VulnerabilityCWEModel.vulnerability_id)\
            .with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = VulnerabilityCWE.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count))\
            .group_by(subquery.c.count). order_by(subquery.c.count)

        count_of_counts = query.all()

        return [GrapheneCount(key=k, value=v) for k, v in count_of_counts]

    def resolve_products_count_by_vendor(self, info):
        subquery = Product.get_query(info).join(VendorModel).group_by(ProductModel.vendor_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Product.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_vulns_by_year(self, info):
        year_exp = sqlalchemy.func.extract('year', VulnerabilityModel.published_date)
        count_exp = sqlalchemy.func.count(VulnerabilityModel.published_date)
        vulns_by_year = Vulnerability.get_query(info).with_entities(year_exp, count_exp).group_by(year_exp).order_by(
            year_exp).all()

        return [GrapheneCount(key=k, value=v) for k, v in vulns_by_year]

    def resolve_vulns_severity(self, info):
        # the following counts the number of vulnerabilities of each severity by the severity field
        query = Vulnerability.get_query(info)
        counts = query.group_by(VulnerabilityModel.severity).with_entities(VulnerabilityModel.severity,
                                                                           sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'N/A', value=v) for k, v in counts]

    def resolve_vulns_exploitability(self, info):
        # the following counts the number of vulnerabilities of each exploitability by the exploitability field
        query = Vulnerability.get_query(info)
        counts = query.group_by(VulnerabilityModel.exploitability).with_entities(VulnerabilityModel.exploitability,
                                                                           sqlalchemy.func.count()).all()

        return [GrapheneCount(key=k if k is not None else 'N/A', value=v) for k, v in counts]

    def resolve_vulns_count_by_vendor(self, info):
        subquery = Vulnerability.get_query(info).join(ConfigurationModel).group_by(ConfigurationModel.vendor_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Vulnerability.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_vulns_count_by_product(self, info):
        subquery = Configuration.get_query(info).group_by(ConfigurationModel.product_id)\
            .with_entities(sqlalchemy.func.coalesce(sqlalchemy.func.count(ConfigurationModel.vulnerability_id), 0).label('count')) \
            .subquery()

        query = Configuration.get_query(info) \
            .with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)) \
            .group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_vulns_count_by_sof_dev_view(self, info):
        sof_dev_categories = Grouping.get_query(info).filter(GroupingModel.parent_id == 699).all()
        categories_id = [x.child_id for x in sof_dev_categories]

        cwe_category = dict(Grouping.get_query(info).filter(GroupingModel.parent_id.in_(categories_id)).
                            with_entities(GroupingModel.child_id, GroupingModel.parent_id).all())

        query = Vulnerability.get_query(info).join(VulnerabilityCWEModel).filter(VulnerabilityCWEModel.cwe_id.in_(cwe_category.keys()))\
            .group_by(VulnerabilityCWEModel.cwe_id).with_entities(VulnerabilityCWEModel.cwe_id, sqlalchemy.func.count().label('count')).all()

        categories_count = {}

        for k, v in query:
            category = cwe_category[k]

            if category not in categories_count:
                categories_count[category] = 0

            categories_count[category] += v

        cwes_name = dict(CWE.get_query(info).filter(CWEModel.id.in_(categories_count.keys())).\
                         with_entities(CWEModel.id, CWEModel.name).all())

        return [GrapheneCount(key=f"CWE-{k}: {cwes_name[k]}", value=v) for k, v in categories_count.items()]

    def resolve_configs_part_count(self, info):
        query = Configuration.get_query(info)

        vuln_cases = sqlalchemy.func.sum(sqlalchemy.case([(ConfigurationModel.vulnerable == True, 1)], else_=0))
        non_vuln_cases = sqlalchemy.func.sum(sqlalchemy.case([(ConfigurationModel.vulnerable == False, 1)], else_=0))

        counts = query.group_by(ConfigurationModel.part).with_entities(ConfigurationModel.part, vuln_cases,
                                                                       non_vuln_cases).all()

        return [NestedGrapheneCount(k, [GrapheneCount('vulnerable', v), GrapheneCount('non-vulnerable', n)]) for k, v, n in counts]

    def resolve_configs_vulns_count(self, info):
        subquery = Vulnerability.get_query(info) \
            .outerjoin(ConfigurationVulnerabilityModel, VulnerabilityModel.id == ConfigurationVulnerabilityModel.vulnerability_id) \
            .group_by(VulnerabilityModel.id) \
            .with_entities(sqlalchemy.func.coalesce(sqlalchemy.func.count(ConfigurationVulnerabilityModel.configuration_id), 0).label('count'))\
            .subquery()

        counts = Vulnerability.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in counts]

    def resolve_configs_count_by_vendor(self, info):
        subquery = Configuration.get_query(info).join(VendorModel).group_by(ConfigurationModel.vendor_id).\
            with_entities(sqlalchemy.func.count().label('count')).subquery()

        query = Configuration.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)).\
            group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]

    def resolve_configs_count_by_product(self, info):
        subquery = Product.get_query(info)\
            .outerjoin(ConfigurationModel, ProductModel.id == ConfigurationModel.product_id) \
            .group_by(ProductModel.id) \
            .with_entities(sqlalchemy.func.coalesce(sqlalchemy.func.count(ConfigurationModel.product_id), 0).label('count'))\
            .subquery()

        query = Product.get_query(info).with_entities(subquery.c.count, sqlalchemy.func.count(subquery.c.count)) \
            .group_by(subquery.c.count).order_by(subquery.c.count).all()

        return [GrapheneCount(key=k, value=v) for k, v in query]
