declare module "enquirer" {
  type PromptInput = Record<string, unknown>;
  type PromptResult<T extends PromptInput> = Promise<T>;
  interface EnquirerModule {
    prompt<T extends PromptInput>(options: PromptInput): PromptResult<T>;
  }
  const Enquirer: EnquirerModule;
  export default Enquirer;
}
