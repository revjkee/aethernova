import docker
from docker.errors import DockerException, NotFound
from typing import List, Optional

class DockerManager:
    def __init__(self):
        self.client = docker.from_env()

    def list_containers(self, all: bool = False) -> List[str]:
        containers = self.client.containers.list(all=all)
        return [container.name for container in containers]

    def start_container(self, container_name: str) -> bool:
        try:
            container = self.client.containers.get(container_name)
            container.start()
            return True
        except NotFound:
            print(f"Container {container_name} not found.")
            return False
        except DockerException as e:
            print(f"Error starting container {container_name}: {e}")
            return False

    def stop_container(self, container_name: str) -> bool:
        try:
            container = self.client.containers.get(container_name)
            container.stop()
            return True
        except NotFound:
            print(f"Container {container_name} not found.")
            return False
        except DockerException as e:
            print(f"Error stopping container {container_name}: {e}")
            return False

    def restart_container(self, container_name: str) -> bool:
        try:
            container = self.client.containers.get(container_name)
            container.restart()
            return True
        except NotFound:
            print(f"Container {container_name} not found.")
            return False
        except DockerException as e:
            print(f"Error restarting container {container_name}: {e}")
            return False

    def remove_container(self, container_name: str, force: bool = False) -> bool:
        try:
            container = self.client.containers.get(container_name)
            container.remove(force=force)
            return True
        except NotFound:
            print(f"Container {container_name} not found.")
            return False
        except DockerException as e:
            print(f"Error removing container {container_name}: {e}")
            return False
