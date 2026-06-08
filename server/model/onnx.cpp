#include <onnxruntime_c_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

//  Config 
#define INPUT_SIZE 440
#define SEQUENCE_LEN 30
#define NUM_CLASSES 3

const char* CLASS_NAMES[] = {"Safe", "Pre-Violence", "Violence"};

//  Helpers 
void check_status(const OrtApi* api, OrtStatus* status) {
    if (status != NULL) {
        const char* msg = api->GetErrorMessage(status);
        fprintf(stderr, "[SafeVision ERROR] %s\n", msg);
        api->ReleaseStatus(status);
        exit(1);
    }
}

void softmax(float* x, int n) {
    float max_val = x[0];
    for (int i = 1; i < n; i++) if (x[i] > max_val) max_val = x[i];
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (int i = 0; i < n; i++) x[i] /= sum;
}

int main(int argc, char** argv) {
    const OrtApi* g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if (!g_ort) {
        fprintf(stderr, "Failed to get ONNX Runtime API\n");
        return 1;
    }

    const char* model_path = "previolence_model.onnx";
    int interactive = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) model_path = argv[++i];
        if (strcmp(argv[i], "--interactive") == 0) interactive = 1;
    }

    OrtEnv* env;
    check_status(g_ort, g_ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "SafeVision", &env));

    OrtSessionOptions* session_options;
    check_status(g_ort, g_ort->CreateSessionOptions(&session_options));
    g_ort->SetIntraOpNumThreads(session_options, 4);
    g_ort->SetSessionGraphOptimizationLevel(session_options, ORT_ENABLE_ALL);

    OrtSession* session;
#ifdef _WIN32
    size_t len = strlen(model_path) + 1;
    wchar_t* wmodel_path = (wchar_t*)malloc(len * sizeof(wchar_t));
    mbstowcs(wmodel_path, model_path, len);
    check_status(g_ort, g_ort->CreateSession(env, wmodel_path, session_options, &session));
    free(wmodel_path);
#else
    check_status(g_ort, g_ort->CreateSession(env, model_path, session_options, &session));
#endif

    size_t input_count;
    check_status(g_ort, g_ort->SessionGetInputCount(session, &input_count));
    
    OrtAllocator* allocator;
    check_status(g_ort, g_ort->GetAllocatorWithDefaultOptions(&allocator));

    char* input_name;
    check_status(g_ort, g_ort->SessionGetInputName(session, 0, allocator, &input_name));
    char* output_name;
    check_status(g_ort, g_ort->SessionGetOutputName(session, 0, allocator, &output_name));

    int64_t input_shape[] = {1, SEQUENCE_LEN, INPUT_SIZE};
    size_t input_tensor_size = SEQUENCE_LEN * INPUT_SIZE;
    float* input_tensor_values = (float*)malloc(input_tensor_size * sizeof(float));

    if (interactive) {
        while (1) {
            size_t read = fread(input_tensor_values, sizeof(float), input_tensor_size, stdin);
            if (read == 0) break;
            if (read < input_tensor_size) continue;

            OrtMemoryInfo* memory_info;
            check_status(g_ort, g_ort->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &memory_info));

            OrtValue* input_tensor = NULL;
            check_status(g_ort, g_ort->CreateTensorWithDataAsOrtValue(
                memory_info, input_tensor_values, input_tensor_size * sizeof(float),
                input_shape, 3, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &input_tensor));
            
            const char* input_names[] = {input_name};
            const char* output_names[] = {output_name};
            OrtValue* output_tensor = NULL;

            check_status(g_ort, g_ort->Run(session, NULL, input_names, (const OrtValue**)&input_tensor, 1, output_names, 1, &output_tensor));

            float* output_values;
            check_status(g_ort, g_ort->GetTensorMutableData(output_tensor, (void**)&output_values));

            softmax(output_values, NUM_CLASSES);

            int pred = 0;
            if (output_values[1] > output_values[0]) pred = 1;

            printf("%d %f %f 0.0\n", pred, output_values[0], output_values[1]);
            fflush(stdout);

            g_ort->ReleaseValue(output_tensor);
            g_ort->ReleaseValue(input_tensor);
            g_ort->ReleaseMemoryInfo(memory_info);
        }
    } else {
        printf("[SafeVision] Standalone mode not implemented in C API demo. Use --interactive\n");
    }

    // Cleanup
    free(input_tensor_values);
    g_ort->ReleaseSession(session);
    g_ort->ReleaseSessionOptions(session_options);
    g_ort->ReleaseEnv(env);

    return 0;
}