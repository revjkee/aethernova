import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
from dataclasses import dataclass
from enum import Enum

from ..base import BaseAgent, Task, Priority

class ReviewSeverity(Enum):
    INFO = "info"
    WARNING = "warning" 
    ERROR = "error"
    CRITICAL = "critical"

class ReviewCategory(Enum):
    CODE_QUALITY = "code_quality"
    PERFORMANCE = "performance"
    SECURITY = "security"
    MAINTAINABILITY = "maintainability"
    DOCUMENTATION = "documentation"
    ARCHITECTURE = "architecture"
    BEST_PRACTICES = "best_practices"

@dataclass
class ReviewComment:
    comment_id: str
    line_number: int
    severity: ReviewSeverity
    category: ReviewCategory
    message: str
    suggestion: str
    rule_name: str
    created_at: datetime

@dataclass
class CodeReviewResult:
    review_id: str
    file_path: str
    reviewer_id: str
    overall_score: float
    comments: List[ReviewComment]
    summary: str
    recommendations: List[str]
    approved: bool
    created_at: datetime

class ReviewerAgent(BaseAgent):
    """Агент ревьюер - проводит ревью кода и документации"""
    
    def __init__(self):
        super().__init__(
            agent_id="role_reviewer",
            name="Code Reviewer",
            capabilities=[
                "code_review", "documentation_review", "architecture_review",
                "security_review", "performance_review", "style_check"
            ]
        )
        self.review_rules = {}
        self.completed_reviews: List[CodeReviewResult] = []
        self.review_standards = {}
        
    async def initialize(self) -> None:
        """Инициализация ревьюера"""
        await self._load_review_rules()
        await self._load_coding_standards()
        self.logger.info("Reviewer Agent initialized")
        
    async def process_task(self, task: Task) -> Dict[str, Any]:
        """Обработка задач ревью"""
        if task.type == "review_code":
            return await self._review_code(task.data)
        elif task.type == "review_architecture":
            return await self._review_architecture(task.data)
        elif task.type == "review_documentation":
            return await self._review_documentation(task.data)
        elif task.type == "security_review":
            return await self._security_review(task.data)
        elif task.type == "performance_review":
            return await self._performance_review(task.data)
        elif task.type == "get_review_stats":
            return await self._get_review_statistics()
        else:
            return {"error": f"Unknown review task: {task.type}"}
            
    async def _review_code(self, review_request: Dict[str, Any]) -> Dict[str, Any]:
        """Проведение ревью кода"""
        file_path = review_request.get("file_path", "")
        code_content = review_request.get("code", "")
        language = review_request.get("language", "python")
        review_type = review_request.get("type", "comprehensive")
        
        if not code_content:
            return {"error": "No code provided for review"}
            
        # Анализ кода
        analysis_results = await self._analyze_code(code_content, language)
        
        # Генерация комментариев
        comments = []
        
        # Проверка стиля кода
        if review_type in ["comprehensive", "style"]:
            style_comments = await self._check_code_style(code_content, language)
            comments.extend(style_comments)
            
        # Проверка качества кода
        if review_type in ["comprehensive", "quality"]:
            quality_comments = await self._check_code_quality(code_content, language)
            comments.extend(quality_comments)
            
        # Проверка безопасности
        if review_type in ["comprehensive", "security"]:
            security_comments = await self._check_security_issues(code_content, language)
            comments.extend(security_comments)
            
        # Проверка производительности
        if review_type in ["comprehensive", "performance"]:
            perf_comments = await self._check_performance_issues(code_content, language)
            comments.extend(perf_comments)
            
        # Расчет общей оценки
        overall_score = await self._calculate_overall_score(comments, analysis_results)
        
        # Определение одобрения
        approved = await self._determine_approval(overall_score, comments)
        
        # Генерация рекомендаций
        recommendations = await self._generate_recommendations(comments, analysis_results)
        
        # Создание результата ревью
        review_result = CodeReviewResult(
            review_id=f"review_{len(self.completed_reviews) + 1}",
            file_path=file_path,
            reviewer_id=self.agent_id,
            overall_score=overall_score,
            comments=comments,
            summary=await self._generate_review_summary(comments, overall_score),
            recommendations=recommendations,
            approved=approved,
            created_at=datetime.now()
        )
        
        self.completed_reviews.append(review_result)
        
        return {
            "review_id": review_result.review_id,
            "overall_score": overall_score,
            "approved": approved,
            "total_comments": len(comments),
            "comments_by_severity": {
                "critical": len([c for c in comments if c.severity == ReviewSeverity.CRITICAL]),
                "error": len([c for c in comments if c.severity == ReviewSeverity.ERROR]),
                "warning": len([c for c in comments if c.severity == ReviewSeverity.WARNING]),
                "info": len([c for c in comments if c.severity == ReviewSeverity.INFO])
            },
            "comments_by_category": await self._categorize_comments(comments),
            "detailed_comments": [
                {
                    "line": c.line_number,
                    "severity": c.severity.value,
                    "category": c.category.value,
                    "message": c.message,
                    "suggestion": c.suggestion
                } for c in comments
            ],
            "summary": review_result.summary,
            "recommendations": recommendations,
            "metrics": analysis_results
        }
        
    async def _review_architecture(self, arch_request: Dict[str, Any]) -> Dict[str, Any]:
        """Ревью архитектуры системы"""
        architecture_doc = arch_request.get("architecture", {})
        design_patterns = arch_request.get("patterns", [])
        requirements = arch_request.get("requirements", {})
        
        # Анализ архитектуры
        arch_analysis = await self._analyze_architecture(architecture_doc)
        
        # Проверка соответствия требованиям
        requirements_check = await self._check_requirements_compliance(architecture_doc, requirements)
        
        # Проверка паттернов проектирования
        patterns_review = await self._review_design_patterns(design_patterns)
        
        # Проверка масштабируемости
        scalability_review = await self._review_scalability(architecture_doc)
        
        # Проверка безопасности архитектуры
        security_review = await self._review_architecture_security(architecture_doc)
        
        return {
            "architecture_score": arch_analysis["score"],
            "requirements_compliance": requirements_check,
            "patterns_review": patterns_review,
            "scalability_assessment": scalability_review,
            "security_assessment": security_review,
            "improvement_suggestions": await self._suggest_architecture_improvements(arch_analysis),
            "risk_factors": await self._identify_architecture_risks(arch_analysis),
            "approval_recommendation": arch_analysis["score"] >= 7.0
        }
        
    async def _review_documentation(self, doc_request: Dict[str, Any]) -> Dict[str, Any]:
        """Ревью документации"""
        documentation = doc_request.get("content", "")
        doc_type = doc_request.get("type", "general")  # api, technical, user, etc.
        
        # Анализ полноты документации
        completeness = await self._analyze_documentation_completeness(documentation, doc_type)
        
        # Проверка качества написания
        quality = await self._analyze_documentation_quality(documentation)
        
        # Проверка структуры
        structure = await self._analyze_documentation_structure(documentation)
        
        # Проверка актуальности
        accuracy = await self._analyze_documentation_accuracy(documentation)
        
        overall_score = (completeness + quality + structure + accuracy) / 4
        
        return {
            "overall_score": overall_score,
            "completeness_score": completeness,
            "quality_score": quality,
            "structure_score": structure,
            "accuracy_score": accuracy,
            "missing_sections": await self._identify_missing_sections(documentation, doc_type),
            "improvement_suggestions": await self._suggest_documentation_improvements(documentation),
            "approval_recommended": overall_score >= 7.5
        }
        
    async def shutdown(self) -> None:
        """Завершение работы ревьюера"""
        await self._save_review_history()
        self.logger.info("Reviewer Agent shutting down")
        
    # Заглушки для методов
    async def _load_review_rules(self):
        self.review_rules = {
            "python": {
                "max_line_length": 88,
                "max_function_length": 50,
                "max_complexity": 10,
                "require_docstrings": True
            }
        }
        
    async def _load_coding_standards(self):
        self.review_standards = {
            "naming": {"use_snake_case": True, "descriptive_names": True},
            "structure": {"max_nesting": 4, "single_responsibility": True}
        }
        
    async def _analyze_code(self, code, language):
        return {
            "lines_of_code": len(code.split('\n')),
            "complexity_score": 5.5,
            "maintainability_index": 75.0,
            "duplication_percentage": 2.1
        }
        
    async def _check_code_style(self, code, language):
        return [
            ReviewComment(
                comment_id="style_1",
                line_number=10,
                severity=ReviewSeverity.WARNING,
                category=ReviewCategory.CODE_QUALITY,
                message="Line too long (95 > 88 characters)",
                suggestion="Break this line into multiple lines",
                rule_name="line_length",
                created_at=datetime.now()
            )
        ]
        
    async def _check_code_quality(self, code, language): return []
    async def _check_security_issues(self, code, language): return []
    async def _check_performance_issues(self, code, language): return []
    async def _calculate_overall_score(self, comments, analysis): return 8.5
    async def _determine_approval(self, score, comments): return score >= 7.0
    async def _generate_recommendations(self, comments, analysis): return ["Add type hints", "Improve error handling"]
    async def _generate_review_summary(self, comments, score): return f"Overall good code quality with score {score}"
    async def _categorize_comments(self, comments): return {"code_quality": 1, "performance": 0}
    async def _analyze_architecture(self, arch): return {"score": 8.0}
    async def _check_requirements_compliance(self, arch, req): return {"compliant": True, "gaps": []}
    async def _review_design_patterns(self, patterns): return {"appropriate": True, "suggestions": []}
    async def _review_scalability(self, arch): return {"scalable": True, "bottlenecks": []}
    async def _review_architecture_security(self, arch): return {"secure": True, "vulnerabilities": []}
    async def _suggest_architecture_improvements(self, analysis): return ["Add caching layer"]
    async def _identify_architecture_risks(self, analysis): return ["Single point of failure"]
    async def _analyze_documentation_completeness(self, doc, doc_type): return 8.0
    async def _analyze_documentation_quality(self, doc): return 7.5
    async def _analyze_documentation_structure(self, doc): return 8.5
    async def _analyze_documentation_accuracy(self, doc): return 9.0
    async def _identify_missing_sections(self, doc, doc_type): return ["Examples", "API reference"]
    async def _suggest_documentation_improvements(self, doc): return ["Add more examples"]
    async def _save_review_history(self): pass
    async def _security_review(self, data): return {"secure": True}
    async def _performance_review(self, data): return {"performance": "good"}
    async def _get_review_statistics(self):
        return {
            "total_reviews": len(self.completed_reviews),
            "average_score": 8.2,
            "approval_rate": 85.0
        }