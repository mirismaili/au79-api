import {R, T, W} from 'anstyle'
import {ESLint} from 'eslint'
import notifier from 'node-notifier'
import {exec as legacyExec} from 'node:child_process'
import {readFile, writeFile} from 'node:fs/promises'
import {normalize, resolve} from 'node:path'
import {promisify} from 'node:util'
import prettier from 'prettier'
import ts from 'typescript'
import packageJson from '../package.json'

const eslint = new ESLint()

const exec = promisify(legacyExec)

console.info(process.cwd())

const {stdout, stderr} = await exec(
  'git diff-tree -r --name-only --diff-filter=ACMRTUXB --no-commit-id HEAD', // https://stackoverflow.com/a/78214581/5318303
)
if (stderr) console.error(stderr)

const trimmedOutput = stdout.trimEnd()
const files = trimmedOutput ? trimmedOutput.split('\n') : [] // Avoid `['']`

if (!files.length) {
  console.info('No new/modified file to commit.')
  process.exit()
}

const ESLINT_INCLUSION_PATTERN = /\.([jt]sx?|[cm]js)$/

const eslintIncludedFiles = []
const notESLintIncludedFiles = []
for (const file of files)
  if (ESLINT_INCLUSION_PATTERN.test(file.toLowerCase())) eslintIncludedFiles.push(file)
  else notESLintIncludedFiles.push(file)

let numFailedChecks = 0
const prettyFilesPromise = prettyFiles(notESLintIncludedFiles).catch(handleError)
const lintFilesPromise = lintFiles(eslintIncludedFiles).catch(handleError)
const checkTsErrorsPromise = checkTsErrors(files).catch(handleError)

await Promise.all([prettyFilesPromise, lintFilesPromise, checkTsErrorsPromise])

if (!numFailedChecks) {
  console.info('\n')
  const title = 'Post-commit checks ✅\xA0\xA0'
  console.info(title)
  notifier.notify({
    title,
    message: 'Prettier + ESLint + TypeScript 👌',
    appID: packageJson.name,
    icon: './.husky/git.svg',
  })
}
// If `process.exit(numFailedChecks)` some notifications may not be shown.

async function prettyFiles(files: string[]) {
  if (!files.length) return console.info('No file to be checked by Prettier.')

  console.group('>> Checking if files are pretty:')
  const results = await Promise.all(
    files.map(async (file) => {
      const {ignored, inferredParser: parser} = await prettier.getFileInfo(file, {
        ignorePath: '.prettierignore', // "getFileInfo() use .prettierignore as default": https://github.com/prettier/prettier/issues/13518
        resolveConfig: false,
      })
      if (ignored || !parser) return {ignored: true}
      const configPromise = prettier.resolveConfig(file)
      const fullFilePath = resolve(file)
      const source = await readFile(file, 'utf-8')
      const formatted = await prettier.format(source, {...(await configPromise), parser})
      if (formatted === source) {
        console.info('✅', fullFilePath)
        return true
      }
      console.error('❌', fullFilePath)
      await writeFile(file, formatted)
      console.info('🔧', fullFilePath)
      return false
    }),
  )
  console.groupEnd()

  const notPrettiedFiles = results.filter((wasPretty) => !wasPretty)
  const numOfNotPrettiedFiles = notPrettiedFiles.length
  if (!numOfNotPrettiedFiles) return

  const err = new Error(
    `Prettier: Found ${numOfNotPrettiedFiles} not-pretty ${numOfNotPrettiedFiles === 1 ? 'file' : 'files'}!\n` +
      'We formatted them for you.\n' +
      'You should "amend commit" them yourself.',
  )
  err.name = '❌ Post-commit Prettier'
  throw err
}

async function lintFiles(files: string[]) {
  if (!files.length) return console.info('No file to be checked by ESLint.')

  const eslintFiles = (
    await Promise.all(files.map(async (file) => await eslint.isPathIgnored(file).then((ignored) => !ignored && file)))
  ).filter(Boolean) as string[] // `false`es are filtered out
  if (!eslintFiles.length) return console.info('No file to be checked by ESLint. All js/ts files were ignored.')

  console.info('>> Linting:\n\t%s\n', eslintFiles.map((path) => resolve(path)).join('\n\t'))

  const results = await eslint.lintFiles(eslintFiles)

  console.info((await eslint.loadFormatter('stylish')).format(results))

  const [numErrors, numWarnings] = results.reduce(
    ([numErrors, numWarnings], {errorCount, warningCount}) => [numErrors + errorCount, numWarnings + warningCount],
    [0, 0],
  )

  const numProblems = numErrors + numWarnings
  if (!numProblems) return

  const err = new Error(`ESLint: ${numProblems} ${numProblems === 1 ? 'problem' : 'problems'}!`)
  err.name = '❌ Post-commit ESLint'
  throw err
}

/** @see https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API */
async function checkTsErrors(files: string[]) {
  const configPath = ts.findConfigFile('./', ts.sys.fileExists.bind(ts.sys))
  if (!configPath) throw new Error("Couldn't find a valid 'tsconfig.json'.")
  const configFileText = await readFile(configPath, 'utf8')
  const {config, error} = ts.readConfigFile(configPath, () => configFileText)
  if (error) {
    console.error(error)
    throw new Error(error.source)
  }
  const basePath = process.cwd() // Current working directory as the base path for resolving paths in tsconfig

  config.compilerOptions.composite = false // This option causes issues if we don't check all project files
  const parsedConfig = ts.parseJsonConfigFileContent(config, ts.sys, basePath)
  const fileNames = parsedConfig.fileNames.map((path) => normalize(path))
  const fullFilePaths = files.map((file) => resolve(file))
  const filteredFiles = fileNames.filter(
    (fileName) => fileName.endsWith('.d.ts') || fullFilePaths.includes(resolve(fileName)),
  )
  if (!filteredFiles.length) return console.info('No file to be checked by Typescript.')

  console.info('>> TSC:\n\t%s\n', filteredFiles.join('\n\t'))

  const program = ts.createProgram(filteredFiles, {...parsedConfig.options, incremental: false}) // Option '--incremental' can only be specified using tsconfig, emitting to single file or when option '--tsBuildInfoFile' is specified.
  const emitResult = program.emit()

  const allDiagnostics = [...ts.getPreEmitDiagnostics(program), ...emitResult.diagnostics]

  allDiagnostics.forEach((diagnostic) => {
    if (!(diagnostic.file && diagnostic.start))
      return console.error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'))
    const {line, character} = ts.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start)
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n')
    console.error(
      `${diagnostic.file.fileName}:${line + 1}:${character + 1} - ${R}error ${W}TS${diagnostic.code}${T}: ${message}`,
    )
  })

  const numProblems = allDiagnostics.length
  if (!numProblems) return
  const err = new Error(`TSC: ${numProblems} ${numProblems === 1 ? 'problem' : 'problems'}!`)
  err.name = '❌ Post-commit TypeScript'
  throw err
}

function handleError(error: Error) {
  numFailedChecks++
  console.error('\n')
  console.error(error)
  notifier.notify({
    title: error.name,
    message: error.message,
    appID: packageJson.name,
    icon: './.husky/git.svg',
  })
  // If `throw error` then `notifier` doesn't `notify`!
}
