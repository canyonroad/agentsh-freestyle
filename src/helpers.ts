import 'dotenv/config'

export function printSection(title: string): void {
  console.log('\n' + '='.repeat(60))
  console.log(title)
  console.log('='.repeat(60))
}

export function printSummary(passed: number, failed: number): void {
  console.log('\n' + '='.repeat(60))
  console.log(`RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed}`)
  console.log('='.repeat(60))
}
