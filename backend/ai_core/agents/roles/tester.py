import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
from dataclasses import dataclass
from enum import Enum

from ..base import BaseAgent, Task, Priority

class TestType(Enum):
    UNIT = "unit"
    INTEGRATION = "integration"
    FUNCTIONAL = "functional"
    PERFORMANCE = "performance"
    SECURITY = "security"
    END_TO_END = "end_to_end"

class TestStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"

@dataclass
class TestCase:
    test_id: str
    name: str
    description: str
    test_type: TestType
    module_under_test: str
    test_code: str
    expected_result: Any
    actual_result: Optional[Any]
    status: TestStatus
    execution_time: float
    created_at: datetime
    last_run: Optional[datetime]

@dataclass
class TestSuite:
    suite_id: str
    name: str
    description: str
    test_cases: List[TestCase]
    setup_code: str
    teardown_code: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    coverage_percentage: float

class TesterAgent(BaseAgent):
    """Агент тестировщик - создает и выполняет тесты"""
    
    def __init__(self):
        super().__init__(
            agent_id="role_tester",
            name="Tester Agent",
            capabilities=[
                "test_creation", "test_execution", "coverage_analysis",
                "performance_testing", "security_testing", "regression_testing"
            ]
        )
        self.test_suites: List[TestSuite] = []
        self.test_cases: List[TestCase] = []
        self.testing_frameworks = {}
        self.coverage_tools = {}
        
    async def initialize(self) -> None:
        """Инициализация тестировщика"""
        await self._setup_testing_frameworks()
        await self._setup_coverage_tools()
        self.logger.info("Tester Agent initialized")
        
    async def process_task(self, task: Task) -> Dict[str, Any]:
        """Обработка задач тестирования"""
        if task.type == "create_tests":
            return await self._create_tests(task.data)
        elif task.type == "run_tests":
            return await self._run_tests(task.data)
        elif task.type == "analyze_coverage":
            return await self._analyze_coverage(task.data)
        elif task.type == "performance_test":
            return await self._performance_test(task.data)
        elif task.type == "security_test":
            return await self._security_test(task.data)
        elif task.type == "regression_test":
            return await self._regression_test(task.data)
        elif task.type == "generate_test_report":
            return await self._generate_test_report(task.data)
        else:
            return {"error": f"Unknown testing task: {task.type}"}
            
    async def _create_tests(self, test_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Создание тестов по спецификациям"""
        module_name = test_spec.get("module_name", "unknown")
        test_types = test_spec.get("test_types", [TestType.UNIT])
        code_to_test = test_spec.get("code", "")
        requirements = test_spec.get("requirements", [])
        
        created_tests = []
        
        for test_type in test_types:
            if test_type == TestType.UNIT:
                unit_tests = await self._create_unit_tests(module_name, code_to_test)
                created_tests.extend(unit_tests)
                
            elif test_type == TestType.INTEGRATION:
                integration_tests = await self._create_integration_tests(module_name, requirements)
                created_tests.extend(integration_tests)
                
            elif test_type == TestType.FUNCTIONAL:
                functional_tests = await self._create_functional_tests(module_name, requirements)
                created_tests.extend(functional_tests)
                
            elif test_type == TestType.PERFORMANCE:
                perf_tests = await self._create_performance_tests(module_name, requirements)
                created_tests.extend(perf_tests)
                
        # Создание тест-сьюта
        test_suite = TestSuite(
            suite_id=f"suite_{len(self.test_suites) + 1}",
            name=f"Test Suite for {module_name}",
            description=f"Comprehensive test suite for {module_name}",
            test_cases=created_tests,
            setup_code=await self._generate_setup_code(module_name),
            teardown_code=await self._generate_teardown_code(module_name),
            total_tests=len(created_tests),
            passed_tests=0,
            failed_tests=0,
            coverage_percentage=0.0
        )
        
        self.test_suites.append(test_suite)
        self.test_cases.extend(created_tests)
        
        return {
            "suite_id": test_suite.suite_id,
            "tests_created": len(created_tests),
            "test_types": [t.name for t in test_types],
            "test_cases": [
                {
                    "test_id": tc.test_id,
                    "name": tc.name,
                    "type": tc.test_type.value,
                    "description": tc.description
                } for tc in created_tests
            ],
            "estimated_execution_time": sum(tc.execution_time for tc in created_tests),
            "recommendations": await self._generate_testing_recommendations(test_suite)
        }
        
    async def _run_tests(self, run_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Выполнение тестов"""
        suite_id = run_spec.get("suite_id")
        test_ids = run_spec.get("test_ids", [])
        parallel = run_spec.get("parallel", False)
        
        if suite_id:
            suite = next((s for s in self.test_suites if s.suite_id == suite_id), None)
            if not suite:
                return {"error": f"Test suite not found: {suite_id}"}
            tests_to_run = suite.test_cases
        else:
            tests_to_run = [tc for tc in self.test_cases if tc.test_id in test_ids]
            
        if not tests_to_run:
            return {"error": "No tests to run"}
            
        # Выполнение тестов
        if parallel:
            results = await self._run_tests_parallel(tests_to_run)
        else:
            results = await self._run_tests_sequential(tests_to_run)
            
        # Обновление статистики
        passed = sum(1 for r in results if r["status"] == TestStatus.PASSED)
        failed = sum(1 for r in results if r["status"] == TestStatus.FAILED)
        errors = sum(1 for r in results if r["status"] == TestStatus.ERROR)
        
        # Обновление тест-сьюта
        if suite_id:
            suite.passed_tests = passed
            suite.failed_tests = failed
            
        execution_summary = {
            "total_tests": len(tests_to_run),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": len(tests_to_run) - passed - failed - errors,
            "success_rate": (passed / len(tests_to_run)) * 100 if tests_to_run else 0,
            "total_execution_time": sum(r["execution_time"] for r in results),
            "detailed_results": results
        }
        
        return execution_summary
        
    async def _analyze_coverage(self, coverage_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Анализ покрытия кода тестами"""
        module_path = coverage_spec.get("module_path", "")
        test_suite_id = coverage_spec.get("suite_id")
        
        if not test_suite_id:
            return {"error": "Test suite ID required for coverage analysis"}
            
        suite = next((s for s in self.test_suites if s.suite_id == test_suite_id), None)
        if not suite:
            return {"error": f"Test suite not found: {test_suite_id}"}
            
        # Анализ покрытия
        coverage_data = await self._calculate_coverage(module_path, suite)
        
        # Обновление сьюта
        suite.coverage_percentage = coverage_data["overall_percentage"]
        
        return {
            "suite_id": test_suite_id,
            "overall_coverage": coverage_data["overall_percentage"],
            "line_coverage": coverage_data["line_coverage"],
            "branch_coverage": coverage_data["branch_coverage"],
            "function_coverage": coverage_data["function_coverage"],
            "uncovered_lines": coverage_data["uncovered_lines"],
            "critical_gaps": coverage_data["critical_gaps"],
            "recommendations": await self._generate_coverage_recommendations(coverage_data)
        }
        
    async def _performance_test(self, perf_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Выполнение тестов производительности"""
        target_function = perf_spec.get("function", "")
        load_profiles = perf_spec.get("load_profiles", [])
        duration = perf_spec.get("duration", 60)
        
        performance_results = []
        
        for profile in load_profiles:
            result = await self._run_load_test(target_function, profile, duration)
            performance_results.append(result)
            
        # Анализ результатов
        analysis = await self._analyze_performance_results(performance_results)
        
        return {
            "target": target_function,
            "test_duration": duration,
            "load_profiles_tested": len(load_profiles),
            "results": performance_results,
            "performance_analysis": analysis,
            "bottlenecks": await self._identify_bottlenecks(performance_results),
            "optimization_suggestions": await self._suggest_optimizations(analysis)
        }
        
    async def shutdown(self) -> None:
        """Завершение работы тестировщика"""
        await self._save_test_results()
        self.logger.info("Tester Agent shutting down")
        
    # Заглушки для методов
    async def _setup_testing_frameworks(self):
        self.testing_frameworks = {
            "python": "pytest",
            "javascript": "jest",
            "java": "junit"
        }
        
    async def _setup_coverage_tools(self):
        self.coverage_tools = {
            "python": "coverage.py",
            "javascript": "istanbul",
            "java": "jacoco"
        }
        
    async def _create_unit_tests(self, module, code):
        return [
            TestCase(
                test_id=f"test_unit_{len(self.test_cases) + 1}",
                name=f"test_{module}_basic",
                description=f"Basic unit test for {module}",
                test_type=TestType.UNIT,
                module_under_test=module,
                test_code="def test_basic(): assert True",
                expected_result=True,
                actual_result=None,
                status=TestStatus.PENDING,
                execution_time=0.0,
                created_at=datetime.now(),
                last_run=None
            )
        ]
        
    async def _create_integration_tests(self, module, req): return []
    async def _create_functional_tests(self, module, req): return []
    async def _create_performance_tests(self, module, req): return []
    async def _generate_setup_code(self, module): return f"# Setup for {module}"
    async def _generate_teardown_code(self, module): return f"# Teardown for {module}"
    async def _generate_testing_recommendations(self, suite): return ["Add edge case tests"]
    async def _run_tests_parallel(self, tests): 
        return [{"test_id": t.test_id, "status": TestStatus.PASSED, "execution_time": 0.1} for t in tests]
    async def _run_tests_sequential(self, tests):
        return [{"test_id": t.test_id, "status": TestStatus.PASSED, "execution_time": 0.1} for t in tests]
    async def _calculate_coverage(self, path, suite):
        return {
            "overall_percentage": 85.5,
            "line_coverage": 87.0,
            "branch_coverage": 82.0,
            "function_coverage": 90.0,
            "uncovered_lines": [42, 67, 89],
            "critical_gaps": ["error_handling", "edge_cases"]
        }
    async def _generate_coverage_recommendations(self, data): return ["Test error paths"]
    async def _run_load_test(self, func, profile, duration): return {"avg_response": 150, "throughput": 1000}
    async def _analyze_performance_results(self, results): return {"bottleneck": "database"}
    async def _identify_bottlenecks(self, results): return ["Database queries", "Memory allocation"]
    async def _suggest_optimizations(self, analysis): return ["Add caching", "Optimize queries"]
    async def _save_test_results(self): pass
    async def _security_test(self, data): return {"vulnerabilities": 0}
    async def _regression_test(self, data): return {"regressions": 0}
    async def _generate_test_report(self, data): return {"report": "generated"}