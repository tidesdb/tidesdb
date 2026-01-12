### When contributing to TidesDB, keep a couple things in mind:

- Make sure your code comments are all lower case and in English and using `/* */` style.
- When adding to tidesdb.c or tidesdb.h please make sure you follow prefixing conventions for internal, public methods.
- Use `code_formatter.sh` to format source code before submitting a pull request.
- Assure your changes are tested and pass all tests.
- Make sure your changes are well documented.

### Developer Certificate of Origin

By contributing to TidesDB, you certify that your contribution was created in whole or in part by you, that you have the right to submit it under the Mozilla Public License Version 2.0, and that you understand and agree that the project and your contribution are public and that a record of the contribution (including all personal information you submit with it) is maintained indefinitely and may be redistributed consistent with the project and the license.

All contributions must include a "Signed-off-by" line in the commit message. This certifies that you agree to the Developer Certificate of Origin (see [Developer Certificate of Origin (DCO)](DCO) file for the full text).

**Note:** DCO sign-off is automatically checked by the [DCO bot](https://github.com/apps/dco) on all pull requests. The bot will show a status check that must pass before your PR can be merged. Pull requests with commits missing sign-off will be blocked until all commits are signed off.

To sign off your commits, use the `-s` or `--signoff` flag:

```bash
git commit -s -m "Your commit message"
```

Or add the following line to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

If you forgot to sign off on previous commits, you can amend them:

```bash
git commit --amend -s
# For multiple commits, use interactive rebase:
git rebase -i HEAD~n  # where n is the number of commits
# Mark commits as 'edit', then run: git commit --amend -s && git rebase --continue
```

You must use your real name and a valid email address. Pseudonyms or anonymous contributions are not allowed.
