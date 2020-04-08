# PostgreSQL mirror
[![Travis-ci Status](https://travis-ci.com/postgrespro/postgres.svg?branch=master_ci)](https://travis-ci.com/postgrespro/postgres)
[![Build status](https://ci.appveyor.com/api/projects/status/24ye5umhokcdyr90/branch/master_ci?svg=true)](https://ci.appveyor.com/project/ololobus/postgres-95nau/branch/master_ci)

Involves automatic builds of PRs/commits on Linux (Travis-CI) and Windows (Appveyor):
  * Linux: full `make check-world`
  * Windows: only build + `make check`

These checks are very similar to [cfbot](https://github.com/postgresql-cfbot) builds.

If you want to verify your patch set before sending it to hackers, then just send a PR with your changes to the branch [master_ci](https://github.com/postgrespro/postgres/tree/master_ci) from any other postgres fork across GitHub. [See example](https://github.com/postgrespro/postgres/pull/3).

Branch [master](https://github.com/postgrespro/postgres/tree/master) is left intact for convinience. Default branch is [master_ci](https://github.com/postgrespro/postgres/tree/master_ci) now, but do not push or commit anything there. To update [master_ci](https://github.com/postgrespro/postgres/tree/master_ci) you should do:

```shell
git checkout master_ci
git pull --rebase upstream master
git push -f origin master_ci
```

For original PostgreSQL readme [refer to README file](README).
