"""业务测试：覆盖8条关键数据链路，验证数据工程操作正确性。"""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.metadata_crawler import MetadataCrawlerService
from app.services.table_catalog import TableCatalogService
from app.services.column_profile import ColumnProfileService
from app.services.lineage_graph import LineageGraphService
from app.services.metric_monitor import MetricMonitorService
from app.services.dq_scorecard import DqScorecardService
from app.services.tag_classify import TagClassifyService
from app.services.dq_template import DqTemplateService
from app.services.dq_rule_def import DqRuleDefService
from app.services.dq_check_run import DqCheckRunService
from app.services.dq_incident import DqIncidentService
from app.services.dq_report import DqReportService
from app.services.anomaly_pattern import AnomalyPatternService
from app.services.metadata_diff import MetadataDiffService
from app.services.dq_alert_channel import DqAlertChannelService
from app.services.dq_baseline import DqBaselineService
from app.services.mdm_entity import MdmEntityService
from app.services.dq_trend import DqTrendService
from app.store import store


class TestMetadataCrawlerPipeline:
    """链路1: 元数据采集器→表目录注册→字段画像计算→分类标签"""

    def test_crawl_metadata_schema(self):
        svc = MetadataCrawlerService()
        schema = svc.crawl_metadata_schema("mysql", "localhost:3306/mydb", "mydb.*")
        assert schema["数据源类型"] == "mysql"
        assert "表清单" in schema
        assert len(schema["表清单"]) > 0
        for tbl in schema["表清单"]:
            assert "表名称" in tbl
            assert "字段列表" in tbl
            assert len(tbl["字段列表"]) > 0

    def test_ingest_metadata_batch(self):
        svc = MetadataCrawlerService()
        schema = svc.crawl_metadata_schema("mysql", "localhost:3306/mydb", "mydb.*")
        result = svc.ingest_metadata_batch(schema)
        assert result["总表数"] > 0
        assert "成功注册" in result

    def test_crawl_hive_schema(self):
        svc = MetadataCrawlerService()
        schema = svc.crawl_metadata_schema("hive", "hdfs://cluster/warehouse", "*.ads_*")
        assert schema["数据源类型"] == "hive"
        for tbl in schema["表清单"]:
            if tbl["表名称"].startswith("ads_"):
                assert tbl["分区字段"] == "dt"

    def test_register_table_with_columns(self):
        svc = TableCatalogService()
        columns = [
            {"字段名称": "id", "数据类型": "BIGINT", "可为空": False, "是否主键": True},
            {"字段名称": "name", "数据类型": "VARCHAR(255)", "可为空": True, "是否主键": False},
            {"字段名称": "amount", "数据类型": "DECIMAL(18,2)", "可为空": True, "是否主键": False},
            {"字段名称": "created_at", "数据类型": "TIMESTAMP", "可为空": False, "是否主键": False},
        ]
        result = svc.register_table_with_columns("ods_order_info", "mysql", columns, 8560000)
        assert result["注册表"] == "ods_order_info"
        assert result["校验问题"] >= 0

    def test_compute_column_statistics(self):
        svc = ColumnProfileService()
        columns = [
            {"字段名称": "id", "数据类型": "BIGINT"},
            {"字段名称": "amount", "数据类型": "DECIMAL(18,2)"},
            {"字段名称": "name", "数据类型": "VARCHAR(255)"},
        ]
        profiles = svc.compute_column_statistics("test_table", columns)
        assert len(profiles) == 3
        for p in profiles:
            assert "空值比例" in p
            assert "唯一值数" in p
            assert "质量评分" in p

    def test_aggregate_table_profile(self):
        svc = ColumnProfileService()
        profiles = svc.compute_column_statistics("test_table", [
            {"字段名称": "id", "数据类型": "BIGINT"},
            {"字段名称": "name", "数据类型": "VARCHAR(255)"},
        ])
        agg = svc.aggregate_table_profile("test_table", profiles)
        assert agg["画像字段数"] == 2
        assert "平均质量评分" in agg
        assert agg["基线已建立"] is True


class TestQualityRulePipeline:
    """链路2: 质量规则定义→巡检任务→质量事件→报告生成"""

    def test_validate_rule_completeness(self):
        svc = DqRuleDefService()
        result = svc.validate_rule_completeness(1)
        assert "校验结果" in result
        assert "问题数量" in result

    def test_compile_rule_to_sql(self):
        svc = DqRuleDefService()
        result = svc.compile_rule_to_sql(1)
        assert "编译SQL" in result
        assert "SELECT" in result["编译SQL"]

    def test_execute_rule_check(self):
        svc = DqRuleDefService()
        result = svc.execute_rule_check(1)
        assert "校验结果" in result
        assert result["校验结果"] in ("通过", "失败")

    def test_schedule_inspection(self):
        svc = DqCheckRunService()
        result = svc.schedule_inspection(
            "DQ_R-0001",
            "质量规则定义样例1,质量规则定义样例2,质量规则定义样例3",
            "0 6 * * *"
        )
        assert result["总规则数"] > 0
        assert "通过数" in result

    def test_write_quality_incident(self):
        svc = DqIncidentService()
        entry = svc.write_quality_incident("DQ_R-0001", "warning", "35%", "ods_order_info")
        assert entry.get("status") == "待确认"
        assert entry.get("abnormal") is not None

    def test_aggregate_quality_report(self):
        svc = DqReportService()
        report = svc.aggregate_quality_report("daily")
        assert "巡检总次数" in report or "巡检通过率" in report

    def test_export_report_csv(self):
        svc = DqReportService()
        # 先生成一份报告
        svc.aggregate_quality_report("daily")
        csv_data = svc.export_report_csv(1)
        if csv_data:
            assert "报告编号" in csv_data


class TestMetricMonitorPipeline:
    """链路3: 巡检任务→指标波动→告警通知"""

    def test_query_metric_values(self):
        svc = MetricMonitorService()
        result = svc.query_metric_values("ods_order_info", "amount", 5000)
        assert result["目标表名"] == "ods_order_info"
        assert "波动幅度" in result
        assert "告警级别" in result

    def test_query_critical_alert(self):
        svc = MetricMonitorService()
        result = svc.query_metric_values("dwd_trade_detail", "amount", 100)
        assert "告警级别" in result

    def test_aggregate_metric_trends(self):
        svc = MetricMonitorService()
        trends = svc.aggregate_metric_trends("ods_order_info", 7)
        assert len(trends) == 7
        for t in trends:
            assert "指标值" in t
            assert "趋势" in t

    def test_dispatch_alert(self):
        svc = DqAlertChannelService()
        result = svc.dispatch_alert("DQ_R-0001", "warning", "指标波动超过阈值30%", "DQ_I-0001")
        assert result["通知方式"] in ("email+sms", "phone+sms", "email")
        assert "接收人" in result

    def test_aggregate_alert_summary(self):
        svc = DqAlertChannelService()
        summary = svc.aggregate_alert_summary(7)
        assert "告警总数" in summary
        assert "按级别" in summary


class TestTrendScorecardPipeline:
    """链路4: 质量事件→趋势分析→评分卡"""

    def test_analyze_incident_trend(self):
        svc = DqIncidentService()
        # 先写入一条关联 ods_order_info 的事件，保证趋势分析有历史数据
        # （此前依赖指标监控测试随机产生的事件，约有两成概率缺失导致用例不稳定）
        svc.write_quality_incident("metric_monitor:ods_order_info.amount", "warning", "35%", "ods_order_info")
        trend = svc.analyze_incident_trend("ods_order_info")
        assert "趋势方向" in trend
        assert "修复率" in trend

    def test_calculate_quality_score(self):
        svc = DqScorecardService()
        result = svc.calculate_quality_score("ods_order_info")
        assert "综合得分" in result
        assert result["综合得分"] > 0
        assert "等级" in result

    def test_compute_quality_trend(self):
        svc = DqTrendService()
        trend = svc.compute_quality_trend("ods_order_info", 7)
        assert trend["目标表名"] == "ods_order_info"
        assert "趋势方向" in trend
        assert "最新质量" in trend

    def test_aggregate_trend_comparison(self):
        svc = DqTrendService()
        result = svc.aggregate_trend_comparison(["ods_order_info", "dwd_trade_detail"])
        assert "排名" in result
        assert len(result["排名"]) >= 1


class TestLineageDiffPipeline:
    """链路5: 元数据采集→变更对比→血缘图谱更新"""

    def test_parse_lineage_from_sql(self):
        svc = LineageGraphService()
        sql = "SELECT * FROM ods_order_info o JOIN dim_product_sku p ON o.sku_id=p.id WHERE o.dt='20260101'"
        lineages = svc.parse_lineage_from_sql(sql, "dws_daily_summary")
        assert len(lineages) > 0
        for lr in lineages:
            assert "上游表名" in lr
            assert lr["下游表名"] == "dws_daily_summary"

    def test_build_lineage_graph(self):
        svc = LineageGraphService()
        # 先构建一些血缘关系
        svc.parse_lineage_from_sql(
            "FROM ods_order_info JOIN dim_product_sku", "dws_daily_summary"
        )
        graph = svc.build_lineage_graph("dws_daily_summary")
        assert graph["中心表"] == "dws_daily_summary"
        assert "上游血缘" in graph

    def test_detect_lineage_breakage(self):
        svc = LineageGraphService()
        breakages = svc.detect_lineage_breakage("dws_daily_summary")
        assert isinstance(breakages, list)

    def test_compare_schemas(self):
        svc = MetadataDiffService()
        old_cols = [
            {"字段名称": "id", "数据类型": "BIGINT", "可为空": False},
            {"字段名称": "name", "数据类型": "VARCHAR(255)", "可为空": True},
            {"字段名称": "old_field", "数据类型": "INTEGER", "可为空": True},
        ]
        new_cols = [
            {"字段名称": "id", "数据类型": "BIGINT", "可为空": False},
            {"字段名称": "name", "数据类型": "TEXT", "可为空": True},
            {"字段名称": "new_field", "数据类型": "VARCHAR(64)", "可为空": False},
        ]
        diff = svc.compare_schemas(old_cols, new_cols, "test_table")
        assert diff["表名称"] == "test_table"
        assert diff["变更总数"] > 0
        assert "旧字段数" in diff
        assert "新增字段" in diff


class TestAnomalyPipeline:
    """链路6: 异常模式训练→检测→事件上报"""

    def test_train_anomaly_pattern(self):
        svc = AnomalyPatternService()
        result = svc.train_anomaly_pattern(1, "7d")
        assert "模型参数" in result
        assert "训练结果" in result

    def test_detect_anomalies(self):
        svc = AnomalyPatternService()
        # 先训练
        svc.train_anomaly_pattern(1, "7d")
        # 检测
        result = svc.detect_anomalies(1)
        assert "检测样本数" in result
        assert "异常点数" in result
        assert "异常率" in result

    def test_classify_tables_by_metadata(self):
        svc = TagClassifyService()
        result = svc.classify_tables_by_metadata(60)
        assert "覆盖表数" in result
        assert "分层统计" in result


class TestBaselinePipeline:
    """链路7: 基线计算→基线校验→事件"""

    def test_calculate_baseline_from_history(self):
        svc = DqBaselineService()
        result = svc.calculate_baseline_from_history("ods_order_info", "row_count")
        assert "上界" in result
        assert "下界" in result
        assert result["均值"] > 0

    def test_check_baseline_deviation(self):
        svc = DqBaselineService()
        # 先建立基线
        svc.calculate_baseline_from_history("ods_order_info", "row_count")
        # 校验偏离
        result = svc.check_baseline_deviation("ods_order_info", 8500)
        assert "校验结果" in result
        assert result["校验结果"] in ("正常", "异常", "无有效基线")


class TestMdmPipeline:
    """链路8: 主数据注册→关联血缘→规则标准化"""

    def test_register_mdm_entity(self):
        svc = MdmEntityService()
        result = svc.register_mdm_entity(
            "product_sku", "商品域",
            ["sku_id", "spu_id"],
            ["sku_id", "spu_id", "sku_name", "category", "price", "status", "created_at"],
            "ERP", "MDM团队"
        )
        assert result["实体名称"] == "product_sku"
        assert result["业务域"] == "商品域"

    def test_validate_entity_consistency(self):
        svc = MdmEntityService()
        # 先注册
        reg = svc.register_mdm_entity(
            "test_entity", "测试域",
            ["id"], ["id", "name", "value"],
            "TEST", "QA"
        )
        # 使用注册返回的实体编号查询
        entity_rows = store.rows("mdm_entity")
        entity_id = max(int(r.get("id", 0)) for r in entity_rows)
        result = svc.validate_entity_consistency(entity_id)
        assert "实体名称" in result


class TestTemplatePipeline:
    """模板标准化链路"""

    def test_standardize_rule_template(self):
        svc = DqTemplateService()
        result = svc.standardize_rule_template(
            "空值率检查模板",
            "空值检查",
            "SELECT COUNT(*) FROM {table} WHERE {column} IS NULL OR {column} = ''",
            ["table", "column"]
        )
        assert result["标准化结果"] == "成功"
        assert "校验详情" in result

    def test_instantiate_template(self):
        svc = DqTemplateService()
        result = svc.instantiate_template(1, {"table": "ods_order_info", "column": "amount"})
        assert "实例化SQL" in result


class TestColdStartBaselineChain:
    """链路9: 稀疏分区冷启动校验→基线待核→统计够用后正式判定"""

    TABLE = "ods_sparse_part"

    def _validate(self, svc, samples, partition):
        return svc.validate_sparse_partition_samples(
            pattern_id=1,
            table_name=self.TABLE,
            partition=partition,
            samples=samples,
            table_upper=12000.0,
            table_lower=4000.0,
            unit="rows",
            min_samples=6,
        )

    def test_sparse_partition_coldstart_record(self):
        """同一分区只有两个新样本，一个高于表级历史阈值 → 产出待复核的冷启动记录。"""
        svc = AnomalyPatternService()
        result = self._validate(svc, [9800.0, 13500.0], partition="dt=2026-11-19")
        assert result["状态"] == "成功"
        record = result["冷启动记录"]
        # 样本不足：只能引用表级历史阈值（稳定时段）作临时阈值
        assert record["样本数"] == 2
        assert record["样本是否充足"] is False
        assert record["训练阶段"] == "冷启动-临时阈值"
        assert record["阈值口径"] == "表级历史阈值(稳定时段)"
        # 越界样本进入待基线复核结论，供值班人员判断是否进异常处置
        assert record["越界样本数"] == 1
        assert "待基线复核" in record["结论"]
        # 原始证据保留在记录里
        assert [s["值"] for s in record["原始样本"]] == [9800.0, 13500.0]
        assert all(s["标签"] == "临时" for s in record["原始样本"])
        assert record["单位"] == "rows"

    def test_temporary_threshold_not_masquerade_as_partition_model(self):
        """样本还不够时，临时阈值不得冒充已经计算过的分区模型。"""
        svc = AnomalyPatternService()
        pattern = store.find("anomaly_pattern", 1)
        version_before = pattern.get("模式版本")
        trained_before = pattern.get("最后训练")
        status_before = pattern.get("status")

        result = self._validate(svc, [9700.0, 13600.0], partition="dt=2026-11-20")
        record = result["冷启动记录"]
        # 记录显式声明自己不是分区模型
        assert record["是否分区模型"] is False
        assert record["训练阶段"] != "统计够用-分区模型"
        # 模式本身也未被推进为已训练
        assert pattern.get("模式版本") == version_before
        assert pattern.get("最后训练") == trained_before
        assert pattern.get("status") == status_before

    def test_training_retry_excludes_temporary_labels(self):
        """训练失败后重试，临时标签不能作为真实观测值回流到训练集。"""
        svc = AnomalyPatternService()
        result = self._validate(svc, [9800.0, 13500.0], partition="dt=2026-11-21")
        record = result["冷启动记录"]
        pattern = store.find("anomaly_pattern", 1)
        version_before = pattern.get("模式版本")

        # 首次训练：候选池只有临时标签样本 → 失败，且不得改动模式
        first = svc.train_anomaly_pattern(1, "7d", candidate_samples=record["原始样本"])
        assert first["训练结果"] == "失败"
        assert first["有效观测样本数"] == 0
        assert first["剔除临时标签样本数"] == 2
        assert pattern.get("模式版本") == version_before

        # 重试：补入真实观测样本，临时标签仍不得回流训练集
        observed = [{"值": 10000.0 + i * 50, "标签": "观测"} for i in range(12)]
        retry = svc.train_anomaly_pattern(
            1, "7d", candidate_samples=record["原始样本"] + observed)
        assert retry["训练结果"] == "成功"
        assert retry["剔除临时标签样本数"] == 2
        assert retry["模型参数"]["清洗前样本数"] == 12
        # 训练集只含真实观测：统计量与临时样本（9800/13500）无关
        assert retry["模型参数"]["均值"] == pytest.approx(10275.0)
        assert retry["模型参数"]["上界(3sigma)"] < 13500.0

    def test_sync_baseline_pending_review(self):
        """训练校验的结论同步到基线待核清单，保留阈值口径、样本条件、单位与训练阶段。"""
        svc = AnomalyPatternService()
        baseline_svc = DqBaselineService()
        result = self._validate(svc, [9800.0, 13500.0], partition="dt=2026-11-22")
        record_no = result["记录编号"]

        sync = baseline_svc.sync_coldstart_review()
        entries = [e for e in sync["待核项明细"] if e["来源记录"] == record_no]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["阈值口径"] == "表级历史阈值(稳定时段)"
        assert entry["样本条件"] == "2/6"
        assert entry["样本是否充足"] is False
        assert entry["单位"] == "rows"
        assert entry["训练阶段"] == "冷启动-临时阈值"
        assert entry["status"] == "待核"

        # 同一记录同一训练阶段重复同步不重复登记
        again = baseline_svc.sync_coldstart_review()
        assert again["新增待核项"] == 0
        remaining = [e for e in baseline_svc.list_pending_reviews() if e["来源记录"] == record_no]
        assert len(remaining) == 1

    def test_continuous_ingest_compare_before_after(self):
        """稀疏分区连续补样：对比统计够用前后的基线校验结果与派发事件，核对临时阶段证据。"""
        svc = AnomalyPatternService()
        baseline_svc = DqBaselineService()
        partition = "dt=2026-11-23"
        incidents = store.rows("dq_incident")

        # 统计够用前：两个新样本，一个高于表级历史阈值
        before = self._validate(svc, [9800.0, 13500.0], partition=partition)
        record_no = before["记录编号"]
        assert before["训练阶段"] == "冷启动-临时阈值"
        info_events = [e for e in incidents
                       if e.get("关联规则") == f"coldstart:{record_no}"]
        assert len(info_events) == 1
        assert info_events[0]["严重级别"] == "info"
        assert info_events[0]["处理状态"] == "冷启动待核"

        baseline_svc.sync_coldstart_review()
        reviews_before = [e for e in baseline_svc.list_pending_reviews()
                          if e["来源记录"] == record_no]
        assert [e["训练阶段"] for e in reviews_before] == ["冷启动-临时阈值"]

        # 连续补入样本直到统计够用
        warning_before = len([e for e in incidents if e.get("严重级别") == "warning"])
        after = self._validate(svc, [10000.0, 10050.0, 9950.0, 10100.0], partition=partition)
        record = after["冷启动记录"]
        assert after["训练阶段"] == "统计够用-分区模型"
        assert record["是否分区模型"] is True
        assert record["阈值口径"] == "分区统计模型(3σ)"
        assert record["样本是否充足"] is True
        # 分区模型仍判定越界 → 派发正式异常事件
        assert after["结论"] == "分区模型判定-异常"
        warning_events = [e for e in incidents if e.get("严重级别") == "warning"]
        assert len(warning_events) == warning_before + 1
        assert warning_events[-1]["处理状态"] == "自动检测"
        assert warning_events[-1]["关联规则"] == f"anomaly:{record['模式编号']}"

        # 统计够用后的基线待核项与之前并存，可按阶段对比
        baseline_svc.sync_coldstart_review()
        reviews = [e for e in baseline_svc.list_pending_reviews()
                   if e["来源记录"] == record_no]
        assert sorted(e["训练阶段"] for e in reviews) == ["冷启动-临时阈值", "统计够用-分区模型"]
        calibers = {e["训练阶段"]: e["阈值口径"] for e in reviews}
        assert calibers["冷启动-临时阈值"] == "表级历史阈值(稳定时段)"
        assert calibers["统计够用-分区模型"] == "分区统计模型(3σ)"
        assert all(e["单位"] == "rows" for e in reviews)
        after_entry = next(e for e in reviews if e["训练阶段"] == "统计够用-分区模型")
        assert after_entry["样本是否充足"] is True
        assert after_entry["结论"] == "分区模型判定-异常"

        # 临时阶段的原始证据仍然留存
        history = record["阶段历史"]
        assert history[0]["阶段"] == "冷启动-临时阈值"
        assert history[0]["样本快照"] == [9800.0, 13500.0]
        assert [s["标签"] for s in record["原始样本"][:2]] == ["临时", "临时"]
        assert [s["标签"] for s in record["原始样本"][2:]] == ["观测"] * 4


class TestDomainSnapshot:
    """测试所有服务的domain_snapshot数据工程操作"""

    def test_all_snapshots_have_operation(self):
        services = [
            MetadataCrawlerService(),
            TableCatalogService(),
            ColumnProfileService(),
            LineageGraphService(),
            MetricMonitorService(),
            DqScorecardService(),
            TagClassifyService(),
            DqTemplateService(),
            DqRuleDefService(),
            DqCheckRunService(),
            DqIncidentService(),
            DqReportService(),
            AnomalyPatternService(),
            MetadataDiffService(),
            DqAlertChannelService(),
            DqBaselineService(),
            MdmEntityService(),
            DqTrendService(),
        ]
        for svc in services:
            snapshot = svc.domain_snapshot()
            assert "operation" in snapshot, f"{svc.MODULE}缺少operation"
            assert "desc" in snapshot, f"{svc.MODULE}缺少desc"
            assert "artifact" in snapshot, f"{svc.MODULE}缺少artifact"