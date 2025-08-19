@echo off
echo Creating LG-SOTF project structure in current directory...

:: Create root files
echo. > pyproject.toml
echo. > setup.py
echo. > requirements.txt
echo. > requirements-dev.txt
echo. > README.md
echo. > .gitignore
echo. > .pre-commit-config.yaml
echo. > pytest.ini
echo. > mypy.ini

:: Create src structure
mkdir src\lg_sotf
echo. > src\lg_sotf\__init__.py

:: Create core module
mkdir src\lg_sotf\core
echo. > src\lg_sotf\core\__init__.py
echo. > src\lg_sotf\core\workflow.py
echo. > src\lg_sotf\core\exceptions.py

:: Create core/state submodule
mkdir src\lg_sotf\core\state
echo. > src\lg_sotf\core\state\__init__.py
echo. > src\lg_sotf\core\state\manager.py
echo. > src\lg_sotf\core\state\model.py
echo. > src\lg_sotf\core\state\history.py
echo. > src\lg_sotf\core\state\serialization.py

:: Create core/nodes submodule
mkdir src\lg_sotf\core\nodes
echo. > src\lg_sotf\core\nodes\__init__.py
echo. > src\lg_sotf\core\nodes\base.py
echo. > src\lg_sotf\core\nodes\ingestion.py
echo. > src\lg_sotf\core\nodes\triage.py
echo. > src\lg_sotf\core\nodes\correlation.py
echo. > src\lg_sotf\core\nodes\analysis.py
echo. > src\lg_sotf\core\nodes\human_loop.py
echo. > src\lg_sotf\core\nodes\response.py
echo. > src\lg_sotf\core\nodes\learning.py

:: Create core/edges submodule
mkdir src\lg_sotf\core\edges
echo. > src\lg_sotf\core\edges\__init__.py
echo. > src\lg_sotf\core\edges\router.py
echo. > src\lg_sotf\core\edges\conditions.py
echo. > src\lg_sotf\core\edges\policies.py
echo. > src\lg_sotf\core\edges\fallback.py

:: Create agents module
mkdir src\lg_sotf\agents
echo. > src\lg_sotf\agents\__init__.py
echo. > src\lg_sotf\agents\base.py
echo. > src\lg_sotf\agents\registry.py

:: Create agents/ingestion submodule
mkdir src\lg_sotf\agents\ingestion
echo. > src\lg_sotf\agents\ingestion\__init__.py
echo. > src\lg_sotf\agents\ingestion\base.py
echo. > src\lg_sotf\agents\ingestion\siem.py
echo. > src\lg_sotf\agents\ingestion\file.py
echo. > src\lg_sotf\agents\ingestion\kafka.py

:: Create agents/triage submodule
mkdir src\lg_sotf\agents\triage
echo. > src\lg_sotf\agents\triage\__init__.py
echo. > src\lg_sotf\agents\triage\base.py
echo. > src\lg_sotf\agents\triage\rules.py
echo. > src\lg_sotf\agents\triage\ml.py

:: Create agents/analysis submodule
mkdir src\lg_sotf\agents\analysis
echo. > src\lg_sotf\agents\analysis\__init__.py
echo. > src\lg_sotf\agents\analysis\base.py
echo. > src\lg_sotf\agents\analysis\react.py
echo. > src\lg_sotf\agents\analysis\tools.py

:: Create agents/human_loop submodule
mkdir src\lg_sotf\agents\human_loop
echo. > src\lg_sotf\agents\human_loop\__init__.py
echo. > src\lg_sotf\agents\human_loop\base.py
echo. > src\lg_sotf\agents\human_loop\escalation.py
echo. > src\lg_sotf\agents\human_loop\feedback.py

:: Create agents/response submodule
mkdir src\lg_sotf\agents\response
echo. > src\lg_sotf\agents\response\__init__.py
echo. > src\lg_sotf\agents\response\base.py
echo. > src\lg_sotf\agents\response\playbook.py
echo. > src\lg_sotf\agents\response\edr.py

:: Create agents/learning submodule
mkdir src\lg_sotf\agents\learning
echo. > src\lg_sotf\agents\learning\__init__.py
echo. > src\lg_sotf\agents\learning\base.py
echo. > src\lg_sotf\agents\learning\rag.py
echo. > src\lg_sotf\agents\learning\fine_tuning.py

:: Create tools module
mkdir src\lg_sotf\tools
echo. > src\lg_sotf\tools\__init__.py
echo. > src\lg_sotf\tools\orchestrator.py
echo. > src\lg_sotf\tools\registry.py

:: Create tools/adapters submodule
mkdir src\lg_sotf\tools\adapters
echo. > src\lg_sotf\tools\adapters\__init__.py
echo. > src\lg_sotf\tools\adapters\base.py

:: Create tools/adapters/siem submodule
mkdir src\lg_sotf\tools\adapters\siem
echo. > src\lg_sotf\tools\adapters\siem\__init__.py
echo. > src\lg_sotf\tools\adapters\siem\base.py
echo. > src\lg_sotf\tools\adapters\siem\splunk.py
echo. > src\lg_sotf\tools\adapters\siem\qradar.py

:: Create tools/adapters/intel submodule
mkdir src\lg_sotf\tools\adapters\intel
echo. > src\lg_sotf\tools\adapters\intel\__init__.py
echo. > src\lg_sotf\tools\adapters\intel\base.py
echo. > src\lg_sotf\tools\adapters\intel\virustotal.py
echo. > src\lg_sotf\tools\adapters\intel\recorded_future.py

:: Create tools/adapters/sandbox submodule
mkdir src\lg_sotf\tools\adapters\sandbox
echo. > src\lg_sotf\tools\adapters\sandbox\__init__.py
echo. > src\lg_sotf\tools\adapters\sandbox\base.py
echo. > src\lg_sotf\tools\adapters\sandbox\joe_sandbox.py
echo. > src\lg_sotf\tools\adapters\sandbox\any_run.py

:: Create tools/adapters/edr submodule
mkdir src\lg_sotf\tools\adapters\edr
echo. > src\lg_sotf\tools\adapters\edr\__init__.py
echo. > src\lg_sotf\tools\adapters\edr\base.py
echo. > src\lg_sotf\tools\adapters\edr\crowdstrike.py
echo. > src\lg_sotf\tools\adapters\edr\sentinelone.py

:: Create tools/strategies submodule
mkdir src\lg_sotf\tools\strategies
echo. > src\lg_sotf\tools\strategies\__init__.py
echo. > src\lg_sotf\tools\strategies\async.py
echo. > src\lg_sotf\tools\strategies\retry.py
echo. > src\lg_sotf\tools\strategies\caching.py
echo. > src\lg_sotf\tools\strategies\fallback.py

:: Create storage module
mkdir src\lg_sotf\storage
echo. > src\lg_sotf\storage\__init__.py
echo. > src\lg_sotf\storage\base.py
echo. > src\lg_sotf\storage\postgres.py
echo. > src\lg_sotf\storage\redis.py
echo. > src\lg_sotf\storage\vector_db.py

:: Create models module
mkdir src\lg_sotf\models
echo. > src\lg_sotf\models\__init__.py
echo. > src\lg_sotf\models\alert.py
echo. > src\lg_sotf\models\state.py
echo. > src\lg_sotf\models\feedback.py
echo. > src\lg_sotf\models\audit.py
echo. > src\lg_sotf\models\workflow.py

:: Create config module
mkdir src\lg_sotf\config
echo. > src\lg_sotf\config\__init__.py
echo. > src\lg_sotf\config\settings.py
echo. > src\lg_sotf\config\logging.py
echo. > src\lg_sotf\config\security.py

:: Create utils module
mkdir src\lg_sotf\utils
echo. > src\lg_sotf\utils\__init__.py
echo. > src\lg_sotf\utils\llm.py
echo. > src\lg_sotf\utils\crypto.py
echo. > src\lg_sotf\utils\monitoring.py
echo. > src\lg_sotf\utils\serialization.py

:: Create audit module
mkdir src\lg_sotf\audit
echo. > src\lg_sotf\audit\__init__.py
echo. > src\lg_sotf\audit\logger.py
echo. > src\lg_sotf\audit\tracer.py
echo. > src\lg_sotf\audit\metrics.py

:: Create tests structure
mkdir tests
echo. > tests\__init__.py
echo. > tests\conftest.py

:: Create tests/unit structure
mkdir tests\unit
echo. > tests\unit\__init__.py

:: Create tests/unit/test_core
mkdir tests\unit\test_core
echo. > tests\unit\test_core\__init__.py
echo. > tests\unit\test_core\test_workflow.py
mkdir tests\unit\test_core\test_state
echo. > tests\unit\test_core\test_state\__init__.py
mkdir tests\unit\test_core\test_nodes
echo. > tests\unit\test_core\test_nodes\__init__.py
mkdir tests\unit\test_core\test_edges
echo. > tests\unit\test_core\test_edges\__init__.py

:: Create tests/unit/test_agents
mkdir tests\unit\test_agents
echo. > tests\unit\test_agents\__init__.py
echo. > tests\unit\test_agents\test_base.py
mkdir tests\unit\test_agents\test_ingestion
echo. > tests\unit\test_agents\test_ingestion\__init__.py
mkdir tests\unit\test_agents\test_triage
echo. > tests\unit\test_agents\test_triage\__init__.py
mkdir tests\unit\test_agents\test_analysis
echo. > tests\unit\test_agents\test_analysis\__init__.py
mkdir tests\unit\test_agents\test_human_loop
echo. > tests\unit\test_agents\test_human_loop\__init__.py
mkdir tests\unit\test_agents\test_response
echo. > tests\unit\test_agents\test_response\__init__.py
mkdir tests\unit\test_agents\test_learning
echo. > tests\unit\test_agents\test_learning\__init__.py

:: Create tests/unit/test_tools
mkdir tests\unit\test_tools
echo. > tests\unit\test_tools\__init__.py
echo. > tests\unit\test_tools\test_orchestrator.py
mkdir tests\unit\test_tools\test_adapters
echo. > tests\unit\test_tools\test_adapters\__init__.py
mkdir tests\unit\test_tools\test_strategies
echo. > tests\unit\test_tools\test_strategies\__init__.py

:: Create other test directories
mkdir tests\unit\test_storage
echo. > tests\unit\test_storage\__init__.py
mkdir tests\unit\test_models
echo. > tests\unit\test_models\__init__.py
mkdir tests\unit\test_config
echo. > tests\unit\test_config\__init__.py
mkdir tests\unit\test_utils
echo. > tests\unit\test_utils\__init__.py
mkdir tests\unit\test_audit
echo. > tests\unit\test_audit\__init__.py

:: Create integration tests
mkdir tests\integration
echo. > tests\integration\__init__.py
echo. > tests\integration\test_workflow.py
echo. > tests\integration\test_agents.py
echo. > tests\integration\test_tools.py
echo. > tests\integration\test_performance.py

:: Create test fixtures
mkdir tests\fixtures
echo. > tests\fixtures\__init__.py
mkdir tests\fixtures\alerts
echo. > tests\fixtures\alerts\__init__.py
mkdir tests\fixtures\configs
echo. > tests\fixtures\configs\__init__.py
mkdir tests\fixtures\responses
echo. > tests\fixtures\responses\__init__.py

:: Create docs structure
mkdir docs
echo. > docs\index.md

mkdir docs\api
echo. > docs\api\core.md
echo. > docs\api\agents.md
echo. > docs\api\tools.md
echo. > docs\api\storage.md

mkdir docs\architecture
echo. > docs\architecture\overview.md
echo. > docs\architecture\state_management.md
echo. > docs\architecture\workflow.md
echo. > docs\architecture\modularity.md

mkdir docs\deployment
echo. > docs\deployment\installation.md
echo. > docs\deployment\configuration.md
echo. > docs\deployment\scaling.md
echo. > docs\deployment\monitoring.md

mkdir docs\examples
echo. > docs\examples\basic_usage.py
echo. > docs\examples\custom_agent.py
echo. > docs\examples\custom_tool.py
mkdir docs\examples\deployment
echo. > docs\examples\deployment\__init__.py

:: Create config files
mkdir configs
echo. > configs\development.yaml
echo. > configs\testing.yaml
echo. > configs\staging.yaml
echo. > configs\production.yaml

:: Create scripts
mkdir scripts
echo. > scripts\setup_db.py
echo. > scripts\run_tests.py
echo. > scripts\deploy.py
echo. > scripts\migrate.py
echo. > scripts\generate_docs.py

:: Create docker files
mkdir docker
echo. > docker\Dockerfile
echo. > docker\Dockerfile.dev
echo. > docker\docker-compose.yml

:: Create k8s files
mkdir k8s
echo. > k8s\namespace.yaml
echo. > k8s\configmap.yaml
echo. > k8s\secrets.yaml
echo. > k8s\deployment.yaml
echo. > k8s\service.yaml
echo. > k8s\ingress.yaml

echo.
echo LG-SOTF project structure created successfully!
echo You can now navigate to the lg-sotf directory and start developing.
echo.
pause