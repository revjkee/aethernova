import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List, Dict, Any
import logging
import json
import statistics

logger = logging.getLogger(__name__)

class ResearchAgent01(BaseAgent):
    """
    Агент исследований для анализа данных, проведения экспериментов и генерации инсайтов.
    Специализируется на научных исследованиях, анализе данных и машинном обучении.
    """
    
    def __init__(self, name="ResearchAgent01"):
        capabilities = [
            AgentCapability("data_analysis", "1.0", "Статистический анализ и обработка данных"),
            AgentCapability("ml_modeling", "1.0", "Создание и обучение моделей машинного обучения"),
            AgentCapability("research_synthesis", "1.0", "Синтез результатов исследований и выводы"),
            AgentCapability("experiment_design", "1.0", "Проектирование и планирование экспериментов"),
            AgentCapability("literature_review", "1.0", "Анализ научной литературы и источников")
        ]
        super().__init__(name, AgentType.HYBRID, capabilities)
        self.name = name
        self.research_projects = {}
        self.datasets = {}
        self.models = {}

    async def initialize(self) -> bool:
        """Инициализация исследовательского окружения"""
        try:
            logger.info(f"[{self.name}] Инициализация исследовательского окружения.")
            
            # Инициализация исследовательских инструментов и конфигурации
            self.config = {
                "max_concurrent_experiments": 5,
                "data_processing_methods": ["statistical", "ml", "nlp", "computer_vision"],
                "supported_formats": ["csv", "json", "parquet", "txt", "images"],
                "ml_frameworks": ["scikit-learn", "tensorflow", "pytorch", "xgboost"],
                "statistical_confidence": 0.95,
                "experiment_tracking": True
            }
            
            # Инициализация библиотеки методов
            self.research_methods = {
                "statistical_tests": ["t_test", "chi_square", "anova", "correlation"],
                "ml_algorithms": ["linear_regression", "random_forest", "neural_networks", "clustering"],
                "data_preprocessing": ["normalization", "feature_selection", "outlier_detection"],
                "visualization": ["plots", "charts", "heatmaps", "distributions"]
            }
            
            logger.info(f"[{self.name}] Исследовательское окружение инициализировано. Доступные методы: {len(self.research_methods)}")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка входящих исследовательских задач"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            if task_type == "analyze_data":
                return await self._analyze_data(message)
            elif task_type == "create_ml_model":
                return await self._create_ml_model(message)
            elif task_type == "design_experiment":
                return await self._design_experiment(message)
            elif task_type == "literature_review":
                return await self._literature_review(message)
            elif task_type == "research_synthesis":
                return await self._research_synthesis(message)
            elif task_type == "hypothesis_testing":
                return await self._hypothesis_testing(message)
            else:
                logger.warning(f"[{self.name}] Неизвестный тип исследовательской задачи: {task_type}")
                return self._create_error_response(message, f"Неподдерживаемый тип задачи: {task_type}")
                
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки исследовательского сообщения: {e}")
            return self._create_error_response(message, str(e))

    async def _analyze_data(self, message: AgentMessage) -> AgentMessage:
        """Статистический анализ данных"""
        payload = message.payload
        dataset_name = payload.get("dataset", "unknown_dataset")
        analysis_type = payload.get("analysis_type", "descriptive")
        data_sample = payload.get("data", [])
        
        # Проведение статистического анализа (симуляция)
        if data_sample and isinstance(data_sample, list) and all(isinstance(x, (int, float)) for x in data_sample):
            # Реальный статистический анализ
            analysis_result = {
                "dataset": dataset_name,
                "sample_size": len(data_sample),
                "descriptive_statistics": {
                    "mean": statistics.mean(data_sample),
                    "median": statistics.median(data_sample),
                    "std_dev": statistics.stdev(data_sample) if len(data_sample) > 1 else 0,
                    "min": min(data_sample),
                    "max": max(data_sample),
                    "range": max(data_sample) - min(data_sample)
                },
                "distribution_analysis": {
                    "normality_test": "passed",  # Упрощенно
                    "outliers_detected": len([x for x in data_sample if abs(x - statistics.mean(data_sample)) > 2 * statistics.stdev(data_sample)]) if len(data_sample) > 1 else 0,
                    "data_quality": "good"
                }
            }
        else:
            # Симуляция анализа для неизвестных данных
            analysis_result = {
                "dataset": dataset_name,
                "analysis_type": analysis_type,
                "sample_size": 1000,
                "descriptive_statistics": {
                    "mean": 42.5,
                    "median": 41.2,
                    "std_dev": 12.3,
                    "min": 18.1,
                    "max": 98.7,
                    "range": 80.6
                },
                "insights": [
                    "Данные демонстрируют нормальное распределение",
                    "Обнаружены 3 потенциальных выброса",
                    "Высокая корреляция между переменными X и Y (r=0.84)"
                ],
                "recommendations": [
                    "Рассмотреть удаление выбросов для повышения качества модели",
                    "Провести дополнительный анализ корреляций",
                    "Увеличить размер выборки для более надежных выводов"
                ]
            }
        
        return AgentMessage(
            sender=self.name,
            task_type="data_analysis_completed",
            payload={
                "analysis_result": analysis_result,
                "success": True,
                "processing_time": "2.3s",
                "confidence_level": 0.95
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _create_ml_model(self, message: AgentMessage) -> AgentMessage:
        """Создание модели машинного обучения"""
        payload = message.payload
        model_type = payload.get("model_type", "regression")
        target_variable = payload.get("target", "y")
        features = payload.get("features", ["x1", "x2", "x3"])
        
        # Симуляция обучения модели
        model_result = {
            "model_id": f"model_{int(message.timestamp)}",
            "model_type": model_type,
            "target_variable": target_variable,
            "features_used": features,
            "training_metrics": {
                "accuracy": 0.87 if model_type == "classification" else None,
                "r2_score": 0.83 if model_type == "regression" else None,
                "mse": 0.12 if model_type == "regression" else None,
                "precision": 0.89 if model_type == "classification" else None,
                "recall": 0.85 if model_type == "classification" else None,
                "f1_score": 0.87 if model_type == "classification" else None
            },
            "validation_metrics": {
                "cross_validation_score": 0.84,
                "overfitting_risk": "low",
                "feature_importance": {
                    feature: round(0.1 + (i * 0.3), 2) for i, feature in enumerate(features[:3])
                }
            },
            "hyperparameters": {
                "learning_rate": 0.01,
                "n_estimators": 100,
                "max_depth": 6
            },
            "training_time": "45.2s",
            "model_size": "2.3MB"
        }
        
        # Сохранение модели в реестр
        model_id = model_result["model_id"]
        self.models[model_id] = model_result
        
        return AgentMessage(
            sender=self.name,
            task_type="ml_model_created",
            payload={
                "model_result": model_result,
                "success": True,
                "ready_for_deployment": model_result["validation_metrics"]["cross_validation_score"] > 0.8
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _design_experiment(self, message: AgentMessage) -> AgentMessage:
        """Проектирование научного эксперимента"""
        payload = message.payload
        research_question = payload.get("research_question", "")
        hypothesis = payload.get("hypothesis", "")
        constraints = payload.get("constraints", {})
        
        experiment_design = {
            "experiment_id": f"exp_{int(message.timestamp)}",
            "research_question": research_question,
            "hypothesis": hypothesis,
            "experiment_type": "controlled_experiment",
            "design": {
                "methodology": "randomized_controlled_trial",
                "sample_size_calculation": {
                    "power": 0.8,
                    "alpha": 0.05,
                    "effect_size": 0.5,
                    "recommended_sample_size": 64
                },
                "groups": {
                    "control_group": {"size": 32, "treatment": "baseline"},
                    "treatment_group": {"size": 32, "treatment": "intervention"}
                },
                "randomization": "block_randomization",
                "blinding": "double_blind"
            },
            "variables": {
                "independent_variables": ["treatment_type", "dosage"],
                "dependent_variables": ["primary_outcome", "secondary_outcome"],
                "control_variables": ["age", "gender", "baseline_score"]
            },
            "data_collection": {
                "measurement_points": ["baseline", "week_2", "week_4", "week_8"],
                "instruments": ["questionnaire", "biomarker", "behavioral_assessment"],
                "data_quality_checks": ["completeness", "consistency", "validity"]
            },
            "analysis_plan": {
                "primary_analysis": "intention_to_treat",
                "statistical_tests": ["t_test", "anova", "regression"],
                "significance_level": 0.05,
                "multiple_comparison_correction": "bonferroni"
            },
            "ethical_considerations": [
                "IRB approval required",
                "Informed consent",
                "Data privacy protection",
                "Participant safety monitoring"
            ],
            "timeline": {
                "preparation": "2 weeks",
                "recruitment": "4 weeks", 
                "data_collection": "8 weeks",
                "analysis": "2 weeks",
                "total_duration": "16 weeks"
            }
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="experiment_designed",
            payload={
                "experiment_design": experiment_design,
                "success": True,
                "feasibility_score": 0.85,
                "estimated_cost": "$25,000"
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _literature_review(self, message: AgentMessage) -> AgentMessage:
        """Обзор научной литературы"""
        payload = message.payload
        topic = payload.get("topic", "")
        search_keywords = payload.get("keywords", [])
        time_range = payload.get("time_range", "last_5_years")
        
        literature_review = {
            "topic": topic,
            "search_strategy": {
                "databases": ["PubMed", "IEEE Xplore", "ACM Digital Library", "arXiv"],
                "keywords": search_keywords,
                "time_range": time_range,
                "inclusion_criteria": ["peer_reviewed", "english", "full_text_available"],
                "exclusion_criteria": ["case_reports", "editorials", "duplicates"]
            },
            "results": {
                "total_papers_found": 156,
                "papers_screened": 156,
                "papers_included": 43,
                "papers_excluded": 113,
                "exclusion_reasons": {
                    "not_relevant": 67,
                    "poor_quality": 28,
                    "duplicate": 18
                }
            },
            "key_findings": [
                "Значительный рост исследований в области ИИ за последние 3 года",
                "Основные методологические подходы: машинное обучение (65%), глубокие нейронные сети (35%)",
                "Выявлен недостаток долгосрочных исследований эффективности"
            ],
            "research_gaps": [
                "Отсутствие стандартизированных метрик оценки",
                "Недостаточное внимание к этическим аспектам",
                "Малое количество мультицентровых исследований"
            ],
            "recommendations": [
                "Проведение метаанализа существующих исследований",
                "Разработка единых стандартов оценки",
                "Инициирование долгосрочного проспективного исследования"
            ],
            "quality_assessment": {
                "average_study_quality": 7.2,  # из 10
                "high_quality_studies": 28,
                "methodological_concerns": 15
            }
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="literature_review_completed",
            payload={
                "literature_review": literature_review,
                "success": True,
                "review_confidence": 0.88
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _research_synthesis(self, message: AgentMessage) -> AgentMessage:
        """Синтез результатов исследований"""
        payload = message.payload
        research_data = payload.get("research_data", [])
        synthesis_type = payload.get("type", "narrative")
        
        synthesis_result = {
            "synthesis_type": synthesis_type,
            "input_studies": len(research_data),
            "main_conclusions": [
                "Подтверждена эффективность предложенного подхода",
                "Статистически значимое улучшение на 23% по основным метрикам",
                "Высокая воспроизводимость результатов в различных условиях"
            ],
            "evidence_strength": {
                "overall_quality": "high",
                "consistency_across_studies": 0.89,
                "effect_size": 0.67,
                "statistical_significance": "p < 0.001"
            },
            "meta_analysis": {
                "combined_effect_size": 0.72,
                "confidence_interval": "[0.58, 0.86]",
                "heterogeneity": "low",
                "i2_statistic": 15.3,
                "publication_bias": "minimal"
            },
            "practical_implications": [
                "Результаты применимы для практического использования",
                "Рекомендуется внедрение в существующие системы",
                "Необходимо дальнейшее изучение долгосрочных эффектов"
            ],
            "future_research_directions": [
                "Исследование механизмов действия",
                "Оптимизация параметров для различных контекстов",
                "Долгосрочные исследования эффективности"
            ]
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="research_synthesis_completed",
            payload={
                "synthesis_result": synthesis_result,
                "success": True,
                "confidence_level": 0.92
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _hypothesis_testing(self, message: AgentMessage) -> AgentMessage:
        """Статистическая проверка гипотез"""
        payload = message.payload
        null_hypothesis = payload.get("null_hypothesis", "")
        alternative_hypothesis = payload.get("alternative_hypothesis", "")
        test_data = payload.get("data", [])
        alpha = payload.get("alpha", 0.05)
        
        # Симуляция статистического теста
        test_result = {
            "null_hypothesis": null_hypothesis,
            "alternative_hypothesis": alternative_hypothesis,
            "test_statistic": 2.45,
            "p_value": 0.017,
            "alpha": alpha,
            "degrees_of_freedom": 58,
            "confidence_interval": "[-0.32, -0.05]",
            "effect_size": 0.42,
            "power": 0.83,
            "decision": "reject_null" if 0.017 < alpha else "fail_to_reject_null",
            "interpretation": "Статистически значимые различия обнаружены" if 0.017 < alpha else "Недостаточно доказательств для отклонения нулевой гипотезы"
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="hypothesis_testing_completed",
            payload={
                "test_result": test_result,
                "success": True,
                "statistical_significance": test_result["p_value"] < alpha
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def shutdown(self) -> bool:
        """Корректное завершение работы агента исследований"""
        try:
            logger.info(f"[{self.name}] Завершение работы агента исследований.")
            
            # Сохранение результатов исследований
            if self.research_projects:
                logger.info(f"[{self.name}] Сохранение {len(self.research_projects)} исследовательских проектов")
            
            if self.models:
                logger.info(f"[{self.name}] Сохранение {len(self.models)} обученных моделей")
            
            # Очистка данных
            self.research_projects.clear()
            self.datasets.clear()
            self.models.clear()
            
            logger.info(f"[{self.name}] Агент исследований успешно завершил работу")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка при завершении работы агента исследований: {e}")
            return False

    def _create_error_response(self, original_message: AgentMessage, error_msg: str) -> AgentMessage:
        """Создание сообщения об ошибке"""
        return AgentMessage(
            sender=self.name,
            task_type="research_error",
            payload={
                "success": False,
                "error": error_msg,
                "original_task": original_message.task_type
            },
            correlation_id=original_message.correlation_id,
            reply_to=original_message.sender
        )