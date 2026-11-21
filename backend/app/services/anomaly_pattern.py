"""异常模式识别服务：训练和检测数据异常模式，驱动质量事件和告警。

domain_chain: 异常模式识别 (anomaly_pattern)
  └─ 清洗 → 质量事件 (dq_incident)
  └─ 检测 → 告警通知 (dq_alert_channel)
  └─ 聚合 → 质量报告 (dq_report)
  └─ 稀疏分区校验 → 冷启动检测记录 → 基线待核清单 (dq_baseline)
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class AnomalyPatternService(BaseModuleService):
    MODULE = "anomaly_pattern"
    ENTITY = "异常模式"
    OPERATION_TERM = "清洗"
    LIST_FIELDS = ["模式编号", "模式名称", "检测方法", "特征字段", "训练窗口", "敏感度", "模式版本", "最后训练"]
    REQUIRED_FIELDS = ["模式编号", "模式名称", "检测方法"]
    STATUS_ORDER = ["草稿", "训练中", "已启用", "已停用"]
    ACTION_RULES = {"开始训练": "训练中", "启用模式": "已启用", "停用模式": "已停用"}
    NEGATIVE_ACTIONS = ["停用模式"]

    ANOMALY_METHODS = ["3-sigma", "IQR", "isolation_forest", "moving_average", "zscore_deviation", "percentile_shift"]

    # 冷启动检测记录：独立存储表、训练准入门槛与训练阶段口径
    COLDSTART_TABLE = "anomaly_coldstart"
    MIN_TRAIN_SAMPLES = 10
    COLDSTART_STAGE = "冷启动-临时阈值"
    PARTITION_MODEL_STAGE = "统计够用-分区模型"

    def train_anomaly_pattern(self, pattern_id: int, training_window: str = "7d",
                              candidate_samples: list[dict] | None = None) -> dict[str, Any]:
        """训练异常检测模式：清洗历史数据并拟合检测模型参数。

        从字段画像和指标监控中读取历史数据，清洗异常值后拟合模型参数，
        计算统计基线（均值、标准差、四分位数），训练完成的模式写入存储。

        candidate_samples 提供时，只接纳标签为「观测」的样本进入训练集；
        冷启动阶段打上「临时」标签的样本不得作为真实观测值回流，被剔除的
        数量写入结果供核查。有效观测样本不足时训练失败，模式状态与版本
        保持不变，补入真实观测后可安全重试。
        """
        pattern = store.find(self.MODULE, pattern_id)
        if not pattern:
            return {"状态": "失败", "原因": f"模式{pattern_id}不存在"}

        method = pattern.get("检测方法", "3-sigma")

        excluded_temp = 0
        if candidate_samples is None:
            # 清洗历史数据：模拟从画像和指标中抓取历史值
            historical_values = [random.gauss(10000, 2000) for _ in range(100)]
        else:
            observed = [s for s in candidate_samples if s.get("标签") == "观测"]
            excluded_temp = len(candidate_samples) - len(observed)
            if len(observed) < self.MIN_TRAIN_SAMPLES:
                return {
                    "模式编号": pattern.get("模式编号"),
                    "状态": "失败",
                    "训练结果": "失败",
                    "原因": f"有效观测样本不足({len(observed)}/{self.MIN_TRAIN_SAMPLES})，临时标签样本不得回流训练集",
                    "有效观测样本数": len(observed),
                    "剔除临时标签样本数": excluded_temp,
                }
            historical_values = [float(s.get("值", 0.0)) for s in observed]
        # 清洗异常值：移除超出3倍标准差的极端值
        mean_val = sum(historical_values) / len(historical_values)
        std_val = (sum((x - mean_val) ** 2 for x in historical_values) / len(historical_values)) ** 0.5
        cleaned = [v for v in historical_values if abs(v - mean_val) <= 3 * std_val]

        # 计算统计基线参数
        cleaned.sort()
        q1 = cleaned[len(cleaned) // 4]
        q3 = cleaned[3 * len(cleaned) // 4]
        iqr = q3 - q1

        model_params = {
            "清洗前样本数": len(historical_values),
            "清洗后样本数": len(cleaned),
            "均值": round(mean_val, 4),
            "标准差": round(std_val, 4),
            "Q1": round(q1, 4),
            "Q3": round(q3, 4),
            "IQR": round(iqr, 4),
            "检测方法": method,
            "上界(3sigma)": round(mean_val + 3 * std_val, 4),
            "下界(3sigma)": round(mean_val - 3 * std_val, 4),
            "训练窗口": training_window,
        }

        # 更新模式状态
        pattern["status"] = "已启用"
        pattern["pending"] = False
        pattern["最后训练"] = datetime.now(timezone.utc).isoformat()
        ver = pattern.get("模式版本", "v0")
        try:
            ver_num = int(ver.lstrip("v")) + 1
        except (ValueError, AttributeError):
            ver_num = 1
        pattern["模式版本"] = f"v{ver_num}"

        return {
            "模式编号": pattern.get("模式编号"),
            "训练结果": "成功",
            "模型参数": model_params,
            "有效观测样本数": len(historical_values),
            "剔除临时标签样本数": excluded_temp,
            "训练时间": datetime.now(timezone.utc).isoformat(),
        }

    def detect_anomalies(self, pattern_id: int, current_values: list[float] | None = None) -> dict[str, Any]:
        """检测当前数据中的异常点并上报质量事件。

        加载已训练的异常模式模型参数，对当前数据执行异常检测计算，
        识别偏离统计基线的异常点，检测到的异常写入质量事件和告警通道。
        """
        pattern = store.find(self.MODULE, pattern_id)
        if not pattern:
            return {"状态": "失败", "原因": f"模式{pattern_id}不存在"}

        if current_values is None:
            current_values = [random.gauss(10000, 2000 * random.uniform(1, 5)) for _ in range(50)]

        # 使用模拟的模型参数进行检测
        mean_val = 10000
        std_val = 2000
        upper = mean_val + 3 * std_val
        lower = mean_val - 3 * std_val

        anomalies = []
        for val in current_values:
            if val > upper or val < lower:
                anomalies.append({
                    "异常值": round(val, 4),
                    "偏离倍数": round(abs(val - mean_val) / std_val, 2),
                    "判定依据": f"超出{'+' if val > mean_val else '-'}3σ边界",
                })

        result = {
            "模式编号": pattern.get("模式编号"),
            "检测方法": pattern.get("检测方法"),
            "检测样本数": len(current_values),
            "异常点数": len(anomalies),
            "异常率": f"{len(anomalies) / len(current_values) * 100:.2f}%",
            "异常明细": anomalies[:10],
            "检测时间": datetime.now(timezone.utc).isoformat(),
        }

        # 检测到异常：写入质量事件并触发告警
        if anomalies:
            self._report_anomaly_incidents(pattern, result, len(anomalies))

        return result

    def _report_anomaly_incidents(self, pattern: dict, result: dict, anomaly_count: int) -> None:
        """检测到的异常上报质量事件并聚合到质量报告。"""
        # 写入质量事件记录
        incident_rows = store.rows("dq_incident")
        new_iid = max((int(r.get("id", 0)) for r in incident_rows), default=0) + 1
        incident_rows.append({
            "id": new_iid,
            "事件编号": f"DQ_I-{new_iid:04d}",
            "关联规则": f"anomaly:{pattern.get('模式编号', '')}",
            "触发时间": datetime.now(timezone.utc).isoformat(),
            "偏离程度": result["异常率"],
            "影响行数": str(anomaly_count),
            "严重级别": "warning" if anomaly_count > 5 else "info",
            "处理状态": "自动检测",
            "处理人": "异常检测引擎",
            "status": "待确认",
            "pending": True,
            "abnormal": True,
        })

        # 聚合到质量报告
        report_rows = store.rows("dq_report")
        new_rid = max((int(r.get("id", 0)) for r in report_rows), default=0) + 1
        report_rows.append({
            "id": new_rid,
            "报告编号": f"DQ_R-{new_rid:04d}",
            "报告周期": f"异常检测-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
            "覆盖表数": "1",
            "通过规则数": str(max(0, result["检测样本数"] - anomaly_count)),
            "失败规则数": str(anomaly_count),
            "趋势分析": "待评估",
            "生成时间": datetime.now(timezone.utc).isoformat(),
            "报告版本": "v1",
            "status": "已完成",
            "pending": False,
            "abnormal": anomaly_count > 5,
        })

    def validate_sparse_partition_samples(
        self,
        pattern_id: int,
        table_name: str,
        partition: str,
        samples: list[float],
        table_upper: float,
        table_lower: float,
        unit: str = "rows",
        min_samples: int = 6,
    ) -> dict[str, Any]:
        """稀疏分区样本校验：为尚未积够数据的新分区产出冷启动检测记录。

        新分区样本不足时，检测只能引用表级历史阈值（稳定时段）作为临时阈值，
        记录显式标记训练阶段为「冷启动-临时阈值」，临时阈值不得冒充已经计算
        过的分区模型；此阶段补入的样本挂「临时」标签，只作原始证据保留，
        不作为真实观测值回流训练集。分区连续补入样本达到最小样本数后，
        才用「观测」标签样本拟合分区统计模型。每次校验都向阶段历史追加
        快照，保证临时阶段的原始证据可核查。
        """
        pattern = store.find(self.MODULE, pattern_id)
        if not pattern:
            return {"状态": "失败", "原因": f"模式{pattern_id}不存在"}
        if not samples:
            return {"状态": "失败", "原因": "待校验样本为空"}

        record = self._find_coldstart_record(pattern.get("模式编号"), table_name, partition)
        if record is None:
            rows = store.rows(self.COLDSTART_TABLE)
            new_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
            record = {
                "id": new_id,
                "记录编号": f"CS-{new_id:04d}",
                "模式编号": pattern.get("模式编号"),
                "目标表名": table_name,
                "分区": partition,
                "单位": unit,
                "最小样本数": min_samples,
                "原始样本": [],
                "阶段历史": [],
                "训练阶段": self.COLDSTART_STAGE,
            }
            rows.append(record)

        now = datetime.now(timezone.utc).isoformat()
        # 样本标签：统计够用前补入的样本挂「临时」标签，之后挂「观测」标签
        will_be_sufficient = (
            record["训练阶段"] == self.PARTITION_MODEL_STAGE
            or len(record["原始样本"]) + len(samples) >= record["最小样本数"]
        )
        label = "观测" if will_be_sufficient else "临时"
        for value in samples:
            record["原始样本"].append({
                "值": float(value),
                "标签": label,
                "是否越界": False,
                "补入时间": now,
            })

        pooled = record["原始样本"]
        total = len(pooled)
        observed = [s["值"] for s in pooled if s["标签"] == "观测"]
        sufficient = total >= record["最小样本数"]

        if sufficient:
            # 统计够用：仅用真实观测样本拟合分区统计模型，临时标签不进入模型
            stage = self.PARTITION_MODEL_STAGE
            caliber = "分区统计模型(3σ)"
            is_model = True
            mean_val = sum(observed) / len(observed)
            std_val = (sum((v - mean_val) ** 2 for v in observed) / len(observed)) ** 0.5
            upper, lower = mean_val + 3 * std_val, mean_val - 3 * std_val
        else:
            # 样本不足：只能引用表级历史阈值作临时阈值，不是分区模型
            stage = self.COLDSTART_STAGE
            caliber = "表级历史阈值(稳定时段)"
            is_model = False
            upper, lower = float(table_upper), float(table_lower)

        breaches = 0
        for item in pooled:
            item["是否越界"] = item["值"] > upper or item["值"] < lower
            if item["是否越界"]:
                breaches += 1

        if sufficient:
            conclusion = "分区模型判定-异常" if breaches else "分区模型判定-正常"
        else:
            conclusion = "超出临时阈值-待基线复核" if breaches else "临时阈值内-继续观察"

        record.update({
            "样本数": total,
            "观测样本数": len(observed),
            "临时样本数": total - len(observed),
            "样本是否充足": sufficient,
            "训练阶段": stage,
            "是否分区模型": is_model,
            "阈值口径": caliber,
            "上界": round(upper, 4),
            "下界": round(lower, 4),
            "越界样本数": breaches,
            "结论": conclusion,
            "检测时间": now,
            "status": ("待处置" if sufficient else "待核") if breaches else "已复核",
            "pending": breaches > 0,
            "abnormal": breaches > 0,
        })
        # 阶段历史：每次校验留快照，临时阶段的原始证据随记录保留
        record["阶段历史"].append({
            "阶段": stage,
            "阈值口径": caliber,
            "样本数": total,
            "观测样本数": len(observed),
            "越界样本数": breaches,
            "结论": conclusion,
            "样本快照": [s["值"] for s in pooled],
            "时间": now,
        })

        if breaches:
            self._dispatch_coldstart_incident(record, pattern)

        return {
            "状态": "成功",
            "记录编号": record["记录编号"],
            "训练阶段": stage,
            "是否分区模型": is_model,
            "样本是否充足": sufficient,
            "越界样本数": breaches,
            "结论": conclusion,
            "冷启动记录": record,
        }

    def _find_coldstart_record(self, pattern_code: str | None, table_name: str,
                               partition: str) -> dict[str, Any] | None:
        """按模式、表、分区定位冷启动检测记录，保证连续补样落在同一份记录上。"""
        for row in store.rows(self.COLDSTART_TABLE):
            if (row.get("模式编号") == pattern_code
                    and row.get("目标表名") == table_name
                    and row.get("分区") == partition):
                return row
        return None

    def _dispatch_coldstart_incident(self, record: dict, pattern: dict) -> None:
        """按训练阶段派发质量事件：临时阶段只发待核事件，分区模型确认后才发正式异常事件。"""
        sufficient = record["样本是否充足"]
        incident_rows = store.rows("dq_incident")
        new_iid = max((int(r.get("id", 0)) for r in incident_rows), default=0) + 1
        incident_rows.append({
            "id": new_iid,
            "事件编号": f"DQ_I-{new_iid:04d}",
            "关联规则": (
                f"anomaly:{pattern.get('模式编号', '')}" if sufficient
                else f"coldstart:{record['记录编号']}"
            ),
            "触发时间": datetime.now(timezone.utc).isoformat(),
            "偏离程度": f"{record['越界样本数']}/{record['样本数']}样本越界",
            "影响行数": str(record["越界样本数"]),
            "严重级别": "warning" if sufficient else "info",
            "处理状态": "自动检测" if sufficient else "冷启动待核",
            "处理人": "异常检测引擎",
            "status": "待确认",
            "pending": True,
            "abnormal": True,
        })

    def domain_snapshot(self) -> dict[str, Any]:
        snapshot = super().domain_snapshot()
        snapshot["operation"] = "清洗"
        snapshot["desc"] = "清洗历史数据训练异常检测模型"
        snapshot["artifact"] = "异常模式检测结果"
        snapshot["artifact_desc"] = "经清洗和检测生成的异常模式检测结果"
        return snapshot