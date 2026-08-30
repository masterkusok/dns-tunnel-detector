# DNS Tunneling detection

> [!NOTE]
> This is a WIP repository. It's modules may be incomplete or reworked in future.  See [TODO list](#todo). 

DNS Tunneling detection framework + CLI tool.

## Contents

- [Getting started](#start)
- [TODO](#todo)


## <a href="#start" id="start" name="start">Getting tarted</a>

> [!WARNING]
> This is article is not ready yet \:\(

## <a href="#todo" id="todo" name="todo">TODO</a>

Here is the short list of things that need to be done in this project:

- [ ] Implement Basic jobs:
    - [ ] Consider redisigning jobs to scoring system
    - [X] Basic heuristic modules
    - [ ] Basic Statistic modules
        - [ ] Cardinality module
            - [ ] Add basic Cardinality counters
            - [ ] Add Distributed counter based on Resid
- [ ] Implement CLI tool:
    - [X] Implement CLI stub resolver with DNS tunneling protection.
    - [ ] Support encrypted DNS protocols in config.
    - [ ] Add Dockerfile.
- [ ] Implement vault (cache)
    - [ ] Implement basic local vault (with persistence)
    - [X] Implement distributed vault
    - [ ] Add invalidation mechanism
- [ ] Documentation:
    - [ ] Improve documentation further.
- [ ] Add precommit hooks/linting scripts.
- [ ] Improve tests, remove crutches and TODOs.