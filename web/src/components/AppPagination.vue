<template>
  <div v-if="total > 0" class="app-pagination" aria-label="分页导航">
    <span class="pagination-summary">共 {{ total }} 条</span>
    <el-pagination
      background
      :current-page="page"
      :page-size="pageSize"
      :page-sizes="pageSizes"
      :total="total"
      layout="sizes, prev, pager, next, jumper"
      @update:current-page="$emit('update:page', $event)"
      @update:page-size="$emit('update:pageSize', $event)"
    />
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  page: number
  pageSize: number
  total: number
  pageSizes?: number[]
}>(), {
  pageSizes: () => [10, 20, 50, 100],
})

defineEmits<{
  'update:page': [value: number]
  'update:pageSize': [value: number]
}>()
</script>

<style scoped lang="scss">
.app-pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1rem 1.25rem;
  border-top: 1px solid var(--color-border);
  overflow-x: auto;
}

.pagination-summary {
  flex-shrink: 0;
  color: var(--color-text-muted);
  font-size: 0.8125rem;
}

@media (max-width: 640px) {
  .app-pagination {
    align-items: flex-start;
    flex-direction: column;
    overflow-x: visible;
  }

  .app-pagination :deep(.el-pagination) {
    width: 100%;
    flex-wrap: wrap;
    justify-content: flex-start;
    row-gap: 0.5rem;
    white-space: normal;
  }
}
</style>
